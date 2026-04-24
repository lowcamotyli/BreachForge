from __future__ import annotations

import asyncio
import json
import re
import time
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

import structlog
from playwright.async_api import Request, Route, async_playwright

from control_plane.auth_manager import SessionSnapshot
from execution_plane.crawler.asset_map import AssetMap, AssetMapBuilder

logger = structlog.get_logger(__name__)

_AUTH_HEADER_KEYS = {"authorization", "cookie", "x-csrf-token", "x-xsrf-token"}
_TRACKED_METHODS = {"POST", "PUT", "PATCH", "DELETE", "GET", "HEAD", "OPTIONS"}
_FORM_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"\baction\s*=\s*(['\"])(?P<url>.+?)\1", re.IGNORECASE | re.DOTALL)
_FORM_METHOD_RE = re.compile(r"\bmethod\s*=\s*(['\"])(?P<method>.+?)\1", re.IGNORECASE | re.DOTALL)
_SCRIPT_CONTENT_RE = re.compile(r"<script\b[^>]*>(?P<content>.*?)</script>", re.IGNORECASE | re.DOTALL)
_FETCH_RE = re.compile(r"""fetch\(\s*(['"])(?P<url>https?://[^'"]+|/[^'"]*)\1""", re.IGNORECASE)
_AXIOS_METHOD_RE = re.compile(
    r"""axios\.(?:get|post|put|patch|delete|head|options)\(\s*(['"])(?P<url>https?://[^'"]+|/[^'"]*)\1""",
    re.IGNORECASE,
)
_AXIOS_CALL_RE = re.compile(r"""axios\(\s*(['"])(?P<url>https?://[^'"]+|/[^'"]*)\1""", re.IGNORECASE)
_XHR_OPEN_RE = re.compile(
    r"""open\(\s*(['"])(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,\s*(['"])(?P<url>https?://[^'"]+|/[^'"]*)\3""",
    re.IGNORECASE,
)


@dataclass(slots=True)
class _CapturedRequest:
    url: str
    method: str
    in_scope: bool
    headers: dict[str, str]
    query_params: list[dict[str, str]]
    body_params: list[dict[str, str]]
    post_data: str | None
    auth_status_code: int | None = None
    observed_content_type: str | None = None
    auth_required: bool = False


class CrawlerReconEngine:
    def __init__(
        self,
        session_snapshot: SessionSnapshot,
        target_url: str,
        scope_domains: list[str],
        timeout_minutes: int = 10,
    ) -> None:
        self._session_snapshot = session_snapshot
        self._target_url = target_url
        self._scope_domains = [domain.lower().strip() for domain in scope_domains if domain.strip()]
        self._timeout_seconds = max(timeout_minutes, 1) * 60
        self._asset_map_builder = AssetMapBuilder()

    async def run(self) -> AssetMap:
        deadline = time.monotonic() + self._timeout_seconds
        captured: dict[tuple[str, str], _CapturedRequest] = {}

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(
                extra_http_headers=self._session_snapshot.auth_headers or None,
                ignore_https_errors=True,
            )
            if self._session_snapshot.cookies:
                await context.add_cookies(self._session_snapshot.cookies)

            async def route_handler(route: Route) -> None:
                if self._is_in_scope(route.request.url):
                    await route.continue_()
                    return
                await route.abort()

            await context.route("**/*", route_handler)
            page = await context.new_page()

            def on_request(request: Request) -> None:
                if request.resource_type not in {"xhr", "fetch"}:
                    return
                if request.method.upper() not in _TRACKED_METHODS:
                    return
                request_url = self._strip_query(request.url)
                query_params = self._extract_query_params(request.url)
                body_params = self._extract_body_params(request.method, request.post_data, request.headers)
                in_scope = self._is_in_scope(request.url)
                key = (request_url, request.method.upper())
                captured[key] = _CapturedRequest(
                    url=request_url,
                    method=request.method.upper(),
                    in_scope=in_scope,
                    headers=dict(request.headers),
                    query_params=query_params,
                    body_params=body_params,
                    post_data=request.post_data,
                )

            def on_response(response: Any) -> None:
                request = response.request
                if request.resource_type not in {"xhr", "fetch"}:
                    return
                request_url = self._strip_query(request.url)
                key = (request_url, request.method.upper())
                observed = captured.get(key)
                if observed is None:
                    return
                observed.auth_status_code = response.status
                observed_content_type = response.headers.get("content-type")
                observed.observed_content_type = observed_content_type

            page.on("request", on_request)
            page.on("response", on_response)

            to_visit: deque[str] = deque([self._target_url])
            visited: set[str] = set()
            while to_visit and time.monotonic() < deadline:
                current = to_visit.popleft()
                if current in visited or not self._is_in_scope(current):
                    continue
                visited.add(current)
                if not await self._navigate(page, current, deadline):
                    break
                await self._capture_discovered_endpoints(page=page, base_url=current, captured=captured)
                for link in await self._extract_discovered_links(page):
                    self._enqueue_discovered_link(link=link, to_visit=to_visit, visited=visited)

            await self._probe_method_coverage(context, captured, deadline)
            await self._annotate_auth_requirements(playwright, captured, deadline)
            await context.close()
            await browser.close()

        for request in captured.values():
            self._asset_map_builder.add_endpoint(
                url=request.url,
                method=request.method,
                in_scope=request.in_scope,
                auth_required=request.auth_required,
                parameters=request.query_params + request.body_params,
                observed_content_type=request.observed_content_type,
                example_response_code=request.auth_status_code,
            )

        asset_map = self._asset_map_builder.build()
        logger.info("crawler_recon_completed", endpoint_count=len(asset_map.endpoints))
        return asset_map

    async def _navigate(self, page: Any, url: str, deadline: float) -> bool:
        remaining_ms = int(max((deadline - time.monotonic()) * 1000, 0))
        if remaining_ms <= 0:
            return False
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=remaining_ms)
            return True
        except Exception:
            return time.monotonic() < deadline

    async def _extract_discovered_links(self, page: Any) -> list[str]:
        hrefs = await page.eval_on_selector_all(
            "a[href]",
            "elements => elements.flatMap(el => [el.getAttribute('href'), el.href]).filter(Boolean)",
        )
        if not isinstance(hrefs, list):
            return []
        links: list[str] = []
        for href in hrefs:
            if not isinstance(href, str):
                continue
            resolved = urljoin(page.url, href)
            parsed = urlparse(resolved)
            if not parsed.hostname:
                continue
            if not self._is_in_scope(resolved):
                continue
            links.append(resolved)
        return links

    def _enqueue_discovered_link(self, link: str, to_visit: deque[str], visited: set[str]) -> None:
        in_scope = self._is_in_scope(link)
        if not in_scope:
            return
        self._asset_map_builder.add_endpoint(
            url=self._strip_query(link),
            method="GET",
            in_scope=in_scope,
            auth_required=False,
            parameters=self._extract_query_params(link),
            observed_content_type=None,
            example_response_code=None,
        )
        if not in_scope:
            return
        if link in visited or link in to_visit:
            return
        to_visit.append(link)

    async def _capture_discovered_endpoints(
        self,
        page: Any,
        base_url: str,
        captured: dict[tuple[str, str], _CapturedRequest],
    ) -> None:
        html_content = await page.content()
        for form in self._extract_form_endpoints(html_content):
            form_url = urljoin(base_url, form["url"])
            if not self._is_in_scope(form_url):
                continue
            method = form["method"].upper()
            key = (self._strip_query(form_url), method)
            captured.setdefault(
                key,
                _CapturedRequest(
                    url=self._strip_query(form_url),
                    method=method,
                    in_scope=True,
                    headers={},
                    query_params=self._extract_query_params(form_url),
                    body_params=[],
                    post_data=None,
                ),
            )

        script_snippets = [*self._extract_inline_scripts(html_content)]
        for script_src in await self._extract_script_sources(page):
            if not self._is_in_scope(script_src):
                continue
            try:
                response = await page.context.request.get(script_src, timeout=3000)
                if response.ok:
                    script_snippets.append(await response.text())
            except Exception:
                continue

        for script in script_snippets:
            for endpoint_url in self._extract_js_fetch_urls(script):
                resolved = urljoin(base_url, endpoint_url)
                if not self._is_in_scope(resolved):
                    continue
                normalized_url = self._strip_query(resolved)
                key = (normalized_url, "GET")
                captured.setdefault(
                    key,
                    _CapturedRequest(
                        url=normalized_url,
                        method="GET",
                        in_scope=True,
                        headers={},
                        query_params=self._extract_query_params(resolved),
                        body_params=[],
                        post_data=None,
                    ),
                )

    async def _extract_script_sources(self, page: Any) -> list[str]:
        sources = await page.eval_on_selector_all(
            "script[src]",
            "elements => elements.map(el => el.src).filter(Boolean)",
        )
        if not isinstance(sources, list):
            return []
        urls: list[str] = []
        for source in sources:
            if not isinstance(source, str):
                continue
            resolved = urljoin(page.url, source)
            if self._is_in_scope(resolved):
                urls.append(resolved)
        return urls

    def _extract_inline_scripts(self, html_content: str) -> list[str]:
        scripts: list[str] = []
        for match in _SCRIPT_CONTENT_RE.finditer(html_content):
            content = match.group("content").strip()
            if content:
                scripts.append(content)
        return scripts

    def _extract_js_fetch_urls(self, js_content: str) -> list[str]:
        discovered: list[str] = []
        for matcher in (_FETCH_RE, _AXIOS_METHOD_RE, _AXIOS_CALL_RE, _XHR_OPEN_RE):
            for match in matcher.finditer(js_content):
                url_value = match.groupdict().get("url")
                if isinstance(url_value, str) and url_value:
                    discovered.append(url_value.strip())
        return discovered

    def _extract_form_endpoints(self, html_content: str) -> list[dict[str, str]]:
        discovered: list[dict[str, str]] = []
        for form_match in _FORM_RE.finditer(html_content):
            form_tag = form_match.group(0)
            action_match = _FORM_ACTION_RE.search(form_tag)
            if action_match is None:
                continue
            method_match = _FORM_METHOD_RE.search(form_tag)
            method = (method_match.group("method") if method_match else "GET").strip().upper()
            if method not in _TRACKED_METHODS:
                method = "GET"
            url = action_match.group("url").strip()
            if not url:
                continue
            discovered.append({"url": url, "method": method})
        return discovered

    async def _probe_method_coverage(
        self,
        context: Any,
        captured: dict[tuple[str, str], _CapturedRequest],
        deadline: float,
    ) -> None:
        base_endpoints = list({request.url for request in captured.values() if request.in_scope})
        for endpoint_url in base_endpoints:
            for probe_method in ("HEAD", "OPTIONS"):
                if time.monotonic() >= deadline:
                    return
                key = (endpoint_url, probe_method)
                if key in captured:
                    continue
                remaining_ms = int(max((deadline - time.monotonic()) * 1000, 0))
                if remaining_ms <= 0:
                    return
                try:
                    response = await context.request.fetch(endpoint_url, method=probe_method, timeout=remaining_ms)
                except Exception:
                    continue
                if response.status == 405:
                    continue
                captured[key] = _CapturedRequest(
                    url=endpoint_url,
                    method=probe_method,
                    in_scope=True,
                    headers={},
                    query_params=self._extract_query_params(endpoint_url),
                    body_params=[],
                    post_data=None,
                    auth_status_code=response.status,
                    observed_content_type=response.headers.get("content-type"),
                )
                if probe_method == "OPTIONS":
                    allow_header = response.headers.get("allow", "")
                    for allow_method in [value.strip().upper() for value in allow_header.split(",") if value.strip()]:
                        if allow_method not in _TRACKED_METHODS:
                            continue
                        allow_key = (endpoint_url, allow_method)
                        captured.setdefault(
                            allow_key,
                            _CapturedRequest(
                                url=endpoint_url,
                                method=allow_method,
                                in_scope=True,
                                headers={},
                                query_params=self._extract_query_params(endpoint_url),
                                body_params=[],
                                post_data=None,
                            ),
                        )

    async def _annotate_auth_requirements(
        self,
        playwright: Any,
        captured: dict[tuple[str, str], _CapturedRequest],
        deadline: float,
    ) -> None:
        unauth_context = await playwright.request.new_context(ignore_https_errors=True)
        try:
            for request in captured.values():
                if time.monotonic() >= deadline or not request.in_scope:
                    break
                unauth_status = await self._probe_without_auth(unauth_context, request, deadline)
                has_auth_headers = any(k.lower() in _AUTH_HEADER_KEYS for k in request.headers)
                request.auth_required = (
                    unauth_status in {401, 403}
                    and (has_auth_headers or (request.auth_status_code is not None and request.auth_status_code not in {401, 403}))
                )
        finally:
            await unauth_context.dispose()

    async def _probe_without_auth(self, request_context: Any, request: _CapturedRequest, deadline: float) -> int | None:
        remaining_ms = int(max((deadline - time.monotonic()) * 1000, 0))
        if remaining_ms <= 0:
            return None
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in _AUTH_HEADER_KEYS
        }
        try:
            response = await request_context.fetch(
                request.url,
                method=request.method,
                headers=headers or None,
                data=request.post_data,
                timeout=remaining_ms,
            )
            return response.status
        except Exception:
            return None

    def _is_in_scope(self, url: str, allowed_domains: list[str] | None = None) -> bool:
        scoped_domains = (
            [domain.lower().strip() for domain in allowed_domains if domain.strip()]
            if allowed_domains is not None
            else self._scope_domains
        )
        hostname = (urlparse(url).hostname or "").lower()
        if not hostname:
            return False
        for domain in scoped_domains:
            if hostname == domain or hostname.endswith(f".{domain}"):
                return True
        return False

    def _strip_query(self, url: str) -> str:
        parsed = urlparse(url)
        return urlunparse(parsed._replace(query="", fragment=""))

    def _extract_query_params(self, url: str) -> list[dict[str, str]]:
        parsed = urlparse(url)
        params: list[dict[str, str]] = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            params.append({"name": key, "location": "query", "type": self._guess_type(value)})
        return params

    def _extract_body_params(self, method: str, post_data: str | None, headers: dict[str, str]) -> list[dict[str, str]]:
        if method.upper() not in {"POST", "PUT", "PATCH"} or not post_data:
            return []
        content_type = headers.get("content-type", "").lower()
        params: list[dict[str, str]] = []
        if "application/json" in content_type:
            try:
                payload = json.loads(post_data)
            except json.JSONDecodeError:
                return []
            if isinstance(payload, dict):
                for key, value in payload.items():
                    params.append({"name": str(key), "location": "body", "type": self._guess_type(value)})
            return params
        if "application/x-www-form-urlencoded" in content_type:
            for key, value in parse_qsl(post_data, keep_blank_values=True):
                params.append({"name": key, "location": "body", "type": self._guess_type(value)})
        return params

    def _guess_type(self, value: Any) -> str:
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "number"
        value_str = str(value)
        if value_str.isdigit():
            return "integer"
        return "string"


def run_crawler(scan_id: str) -> None:
    """RQ-callable entrypoint for reconnaissance phase."""
    asyncio.run(_run_crawler_async(scan_id))


async def _run_crawler_async(scan_id: str) -> None:
    from uuid import UUID

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from control_plane.auth_manager import AuthManager, default_pause_scan
    from control_plane.orchestrator import ScanOrchestrator
    from control_plane.reporting import ReportingService
    from storage.db.models import AssetMap as AssetMapRecord
    from storage.db.models import AuthContext, Endpoint as EndpointRecord, Scan, Target
    from storage.db.session import AsyncSessionLocal
    from storage.evidence.store import EvidenceStore

    scan_uuid = UUID(scan_id)
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Scan)
                .where(Scan.id == scan_uuid)
                .options(
                    selectinload(Scan.target),
                    selectinload(Scan.auth_context),
                )
            )
            scan = result.scalar_one_or_none()
            if scan is None:
                raise LookupError(f"Scan not found: {scan_id}")

            target = scan.target
            if target is None:
                raise LookupError(f"Target not found for scan: {scan_id}")
            if not isinstance(target, Target):
                raise LookupError(f"Invalid target relation for scan: {scan_id}")

            auth_context = scan.auth_context
            if auth_context is None:
                raise LookupError(f"Auth context not found for scan: {scan_id}")
            if not isinstance(auth_context, AuthContext):
                raise LookupError(f"Invalid auth context relation for scan: {scan_id}")

            target_url = target.url
            target_config = target.config if isinstance(target.config, dict) else {}
            raw_domains = target_config.get("allowed_domains")
            scope_domains = (
                [domain for domain in raw_domains if isinstance(domain, str) and domain.strip()]
                if isinstance(raw_domains, list)
                else []
            )
            if not scope_domains:
                parsed_target_host = urlparse(target_url).hostname
                if isinstance(parsed_target_host, str) and parsed_target_host:
                    scope_domains = [parsed_target_host]

            snapshot_payload = auth_context.session_snapshot if isinstance(auth_context.session_snapshot, dict) else {}
            auth_type = auth_context.type

        from control_plane.auth_manager import _build_auth_input_from_snapshot

        auth_manager = AuthManager(scan_uuid, AsyncSessionLocal, default_pause_scan)
        try:
            auth_input = _build_auth_input_from_snapshot(auth_type, snapshot_payload, scan_uuid)
            await auth_manager.bootstrap(auth_input)
            session_snapshot = await auth_manager.get_session_snapshot(scan_uuid)
        finally:
            await auth_manager.close()

        engine = CrawlerReconEngine(
            session_snapshot=session_snapshot,
            target_url=target_url,
            scope_domains=scope_domains,
        )
        asset_map = await engine.run()

        to_dict_method = getattr(asset_map, "to_dict", None)
        if callable(to_dict_method):
            asset_map_dict = to_dict_method()
        else:
            asset_map_dict = {
                "target_url": target_url,
                "endpoints": [
                    {
                        "url_pattern": endpoint.url_pattern,
                        "method": endpoint.method,
                        "in_scope": endpoint.in_scope,
                        "auth_required": endpoint.auth_required,
                        "parameters": endpoint.parameters,
                        "observed_content_type": endpoint.observed_content_type,
                        "example_response_code": endpoint.example_response_code,
                    }
                    for endpoint in asset_map.endpoints
                ],
            }

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Scan)
                .where(Scan.id == scan_uuid)
                .options(selectinload(Scan.asset_map).selectinload(AssetMapRecord.endpoints))
            )
            scan_record = result.scalar_one_or_none()
            if scan_record is None:
                raise LookupError(f"Scan not found for asset-map persistence: {scan_id}")

            asset_map_record = scan_record.asset_map
            if asset_map_record is None:
                asset_map_record = AssetMapRecord(scan_id=scan_uuid)
                db.add(asset_map_record)
                await db.flush()
            else:
                asset_map_record.endpoints.clear()
                await db.flush()

            for endpoint in asset_map.endpoints:
                db.add(
                    EndpointRecord(
                        asset_map_id=asset_map_record.id,
                        url_pattern=endpoint.url_pattern,
                        method=endpoint.method,
                        auth_required=endpoint.auth_required,
                        parameters=endpoint.parameters,
                        observed_content_type=endpoint.observed_content_type,
                        example_response_code=endpoint.example_response_code,
                    )
                )

            await db.commit()

        async with AsyncSessionLocal() as db:
            evidence_store = EvidenceStore()
            reporting_service = ReportingService(db=db, evidence_store=evidence_store)
            orchestrator = ScanOrchestrator(AsyncSessionLocal, reporting_service)
            await orchestrator.on_recon_complete(scan_uuid, asset_map_dict)
    except Exception as exc:
        logger.exception("crawler_recon_failed", scan_id=scan_id, error=str(exc))
        try:
            async with AsyncSessionLocal() as db:
                evidence_store = EvidenceStore()
                reporting_service = ReportingService(db=db, evidence_store=evidence_store)
                orchestrator = ScanOrchestrator(AsyncSessionLocal, reporting_service)
                await orchestrator.on_scan_failed(scan_uuid, str(exc))
        except Exception as failure_exc:
            logger.exception("crawler_recon_failure_handler_failed", scan_id=scan_id, error=str(failure_exc))
        raise
