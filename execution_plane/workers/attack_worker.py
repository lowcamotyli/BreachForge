from __future__ import annotations

import asyncio
import json
import os
import random
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx
import structlog
from redis import Redis

from control_plane.auth_manager import AuthManager, IdentityRole, SessionSnapshot
from control_plane.rate_limiter import DomainRateLimiter
from execution_plane.workers.behavior_profiles import BehaviorConfig, BehaviorProfile, get_profile_config
from storage.evidence.state_store import StateSnapshot, StateStore
from storage.db.models import AttackTask, RawProbe

logger = structlog.get_logger(__name__)
_SENSITIVE_LOG_KEYS = {"authorization", "cookie", "x-auth-token", "password", "token", "x-api-key"}


class GuardrailViolation(RuntimeError):
    pass


class AttackWorker:
    def __init__(
        self,
        redis_client: Redis | None = None,
        rate_limiter: DomainRateLimiter | None = None,
        auth_manager: AuthManager | None = None,
        behavior_profile: BehaviorProfile = BehaviorProfile.low_and_slow,
    ) -> None:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._redis = redis_client or Redis.from_url(redis_url, decode_responses=True)
        self._rate_limiter = rate_limiter or DomainRateLimiter(redis_client=self._redis)
        self._auth_manager = auth_manager
        self._behavior_config: BehaviorConfig = get_profile_config(behavior_profile)
        self._state_store = StateStore()
        self._snapshot_versions: dict[tuple[str, str], int] = {}
        self._rate_limit_wait_timeout_s = max(0.0, float(os.getenv("RATE_LIMIT_WAIT_TIMEOUT_S", "15")))

    async def execute(
        self,
        task: AttackTask,
        session: SessionSnapshot,
        identity_role: IdentityRole | str | None = None,
    ) -> RawProbe:
        self._save_state_snapshot(task=task, status="pre")
        endpoint = task.endpoint
        if endpoint is None:
            self._save_state_snapshot(task=task, status="failed")
            raise ValueError("AttackTask.endpoint must be loaded before execute()")

        execution_session = session
        if identity_role is not None:
            if self._auth_manager is None:
                self._save_state_snapshot(task=task, status="failed")
                raise GuardrailViolation("identity_role requires AttackWorker(auth_manager=...)")
            identity_context = await self._auth_manager.get_identity_context(scan_id=task.scan_id, role=identity_role)
            execution_session = identity_context.to_session_snapshot()
        raw_probe: RawProbe | None = None
        try:
            hypothesis_config = self._parse_hypothesis(task.hypothesis)
            chain_steps = hypothesis_config.get("chain_steps")
            if isinstance(chain_steps, list) and chain_steps:
                raw_probe = await self._execute_chain_steps(
                    task=task,
                    session=execution_session,
                    steps=chain_steps,
                    hypothesis_config=hypothesis_config,
                )
            else:
                method = endpoint.method.upper()
                url = endpoint.url_pattern
                probe_type = hypothesis_config.get("probe_type")
                request_headers = self._build_probe_headers(session=execution_session, probe_type=probe_type)
                request_body = self._build_request_body(task)
                worker_id = self._worker_id()

                domain = self._extract_request_domain(url)
                allowed_domains = self._resolve_allowed_domains(task)
                if not self._is_domain_allowed(domain, allowed_domains):
                    raise GuardrailViolation(
                        f"Out-of-scope target domain '{domain}' for task {task.id}; allowed domains: {sorted(allowed_domains)}"
                    )

                if (
                    self._rate_limiter.production_safe_mode
                    and not self._rate_limiter.allow_mutating_methods
                    and method in DomainRateLimiter.MUTATING_METHODS
                ):
                    raise GuardrailViolation(f"Mutating method '{method}' blocked in production-safe mode")

                await self._enforce_rate_limit(scan_id=str(task.scan_id), domain=domain, method=method, worker_id=worker_id)
                await self._apply_timing_profile(hypothesis_config.get("timing_profile"))

                cookies = self._build_probe_cookies(session=execution_session, probe_type=probe_type)
                async with httpx.AsyncClient(headers=request_headers, cookies=cookies, follow_redirects=True) as client:
                    request, response, latency_ms = await self._send_request(
                        client=client,
                        method=method,
                        url=url,
                        content=request_body,
                    )

                raw_probe = self._build_raw_probe(
                    task=task,
                    worker_id=worker_id,
                    request=request,
                    response=response,
                    latency_ms=latency_ms,
                )

                evidence_metadata: dict[str, str] = {}
                if probe_type == "replay":
                    evidence_metadata["chain_id"] = f"{task.id}_replay"
                    logger.info(
                        "attack_probe_chain_entry",
                        attack_task_id=str(task.id),
                        entry=self._strip_sensitive({"chain_step": 1, "probe_type": "replay", "reused_token": True}),
                    )

                mutation_class = self._mutation_class_for_probe_type(probe_type)
                if mutation_class is not None:
                    evidence_metadata["mutation_class"] = mutation_class

                await self._publish_evidence(task.scan_id, raw_probe, metadata=evidence_metadata or None)
        except Exception:
            self._save_state_snapshot(task=task, status="failed")
            raise

        status_value = raw_probe.response.get("status") if isinstance(raw_probe.response, dict) else None
        response_status_code = status_value if isinstance(status_value, int) else None
        self._save_state_snapshot(task=task, status="post", response_status_code=response_status_code)
        return raw_probe

    async def _enforce_rate_limit(self, scan_id: str, domain: str, method: str, worker_id: str) -> None:
        def _acquire() -> bool:
            return self._rate_limiter.acquire_for_worker(scan_id=scan_id, domain=domain, worker_id=worker_id, method=method)

        deadline = time.monotonic() + self._rate_limit_wait_timeout_s
        while True:
            allowed = await asyncio.to_thread(_acquire)
            if allowed:
                return
            if time.monotonic() >= deadline:
                raise GuardrailViolation(
                    f"Rate-limiter denied request for scan={scan_id}, domain={domain}, worker={worker_id}, method={method}"
                )
            await asyncio.sleep(0.25)

    def _resolve_allowed_domains(self, task: AttackTask) -> set[str]:
        scan = task.scan
        if scan is None or scan.target is None:
            raise GuardrailViolation("AttackTask.scan.target must be loaded to enforce allowed_domains")

        config = scan.target.config
        if not isinstance(config, dict):
            raise GuardrailViolation("Target config must be a dict containing allowed_domains")

        allowed_domains = config.get("allowed_domains")
        if not isinstance(allowed_domains, list):
            raise GuardrailViolation("Target config.allowed_domains must be a non-empty list")

        normalized = {
            self._normalize_domain(value)
            for value in allowed_domains
            if isinstance(value, str) and self._normalize_domain(value)
        }
        if not normalized:
            raise GuardrailViolation("Target config.allowed_domains must include at least one valid domain")
        return normalized

    def _extract_request_domain(self, url: str) -> str:
        parsed = urlparse(url)
        domain = self._normalize_domain(parsed.hostname)
        if not domain:
            raise GuardrailViolation(f"Task URL has no valid host: {url}")
        return domain

    def _is_domain_allowed(self, domain: str, allowed_domains: set[str]) -> bool:
        for allowed in allowed_domains:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True
        return False

    def _normalize_domain(self, domain: str | None) -> str:
        if not domain:
            return ""
        return domain.strip().lower().rstrip(".")

    async def _publish_evidence(self, scan_id: Any, raw_probe: RawProbe, metadata: dict[str, str] | None = None) -> None:
        stream_key = f"evidence:{scan_id}"
        # Evidence stored unredacted per invariant #6; redaction at ReportingService only.
        payload = {
            "attack_task_id": str(raw_probe.attack_task_id),
            "worker_id": raw_probe.worker_id,
            "timestamp": raw_probe.timestamp.isoformat(),
            "request": json.dumps(raw_probe.request),
            "response": json.dumps(raw_probe.response),
        }
        if metadata:
            payload.update(metadata)

        await asyncio.to_thread(self._redis.xadd, stream_key, payload)
        logger.info(
            "attack_probe_published",
            scan_id=str(scan_id),
            attack_task_id=str(raw_probe.attack_task_id),
            stream_key=stream_key,
            metadata=self._strip_sensitive(metadata or {}),
            request=self._strip_sensitive(raw_probe.request),
            response=self._strip_sensitive(raw_probe.response),
        )

    def _strip_sensitive(self, value: dict[str, Any]) -> dict[str, Any]:
        stripped: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in _SENSITIVE_LOG_KEYS:
                continue
            if isinstance(item, dict):
                stripped[key] = self._strip_sensitive(item)
            else:
                stripped[key] = item
        return stripped

    def _build_request_headers(self, session: SessionSnapshot) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in session.auth_headers.items():
            headers[key] = value
        for key, value in session.csrf_tokens.items():
            headers[key] = value
        return headers

    def _build_probe_headers(self, session: SessionSnapshot, probe_type: Any) -> dict[str, str]:
        if probe_type == "impact_unauthenticated_repeat":
            return {}

        if probe_type == "replay":
            replay_headers: dict[str, str] = {}
            for key, value in session.auth_headers.items():
                replay_headers[key] = value
            return replay_headers

        headers = self._build_request_headers(session)
        if probe_type == "token_swap":
            for key, value in list(headers.items()):
                if key.lower() in {"authorization", "x-auth-token"}:
                    headers[key] = f"{value}_swapped"
        elif probe_type == "stale_session":
            headers["X-Session-Age"] = "99999"
        return headers

    def _build_probe_cookies(self, session: SessionSnapshot, probe_type: Any) -> httpx.Cookies:
        if probe_type == "impact_unauthenticated_repeat":
            return httpx.Cookies()
        return self._to_httpx_cookies(session.cookies)

    def _build_request_body(self, task: AttackTask) -> bytes | None:
        if not task.hypothesis:
            return None
        return task.hypothesis.encode("utf-8")

    def _parse_hypothesis(self, hypothesis: str | None) -> dict[str, Any]:
        if not hypothesis:
            return {}
        try:
            parsed = json.loads(hypothesis)
        except json.JSONDecodeError:
            return {}
        if not isinstance(parsed, dict):
            return {}
        return parsed

    async def _apply_timing_profile(self, timing_profile: Any) -> None:
        if not isinstance(timing_profile, dict):
            return

        think_time_ms_raw = timing_profile.get("think_time_ms", 0)
        jitter_ms_raw = timing_profile.get("jitter_ms", 0)
        think_time_ms = min(max(self._coerce_int(think_time_ms_raw), 0), 2000)
        jitter_ms = min(max(self._coerce_int(jitter_ms_raw), 0), 500)

        if think_time_ms > 0:
            await asyncio.sleep(think_time_ms / 1000)
        if jitter_ms > 0:
            await asyncio.sleep(random.uniform(0.0, jitter_ms / 1000))

    def _coerce_int(self, value: Any) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return 0
        return 0

    def _mutation_class_for_probe_type(self, probe_type: Any) -> str | None:
        if probe_type == "token_swap":
            return "token_swap"
        if probe_type == "stale_session":
            return "stale_session"
        return None

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[httpx.Request, httpx.Response, int]:
        if self._behavior_config.request_delay_ms > 0:
            await asyncio.sleep(self._behavior_config.request_delay_ms / 1000)
        if headers is None and params is None:
            request = client.build_request(method=method, url=url, content=content)
        else:
            try:
                request = client.build_request(method=method, url=url, content=content, headers=headers, params=params)
            except TypeError:
                request = client.build_request(method=method, url=url, content=content)
                if headers:
                    request.headers.update(headers)
                if params:
                    request.url = request.url.copy_merge_params(params)
        start = time.perf_counter()
        response = await client.send(request)
        latency_ms = int((time.perf_counter() - start) * 1000)
        return request, response, latency_ms

    def _build_raw_probe(
        self,
        task: AttackTask,
        worker_id: str,
        request: httpx.Request,
        response: httpx.Response,
        latency_ms: int,
    ) -> RawProbe:
        return RawProbe(
            id=uuid4(),
            attack_task_id=task.id,
            worker_id=worker_id,
            timestamp=datetime.now(UTC),
            request={
                "method": request.method,
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": self._decode_request_body(request.content),
            },
            response={
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
                "latency_ms": latency_ms,
            },
        )

    async def _execute_chain_steps(
        self,
        task: AttackTask,
        session: SessionSnapshot,
        steps: list[Any],
        hypothesis_config: dict[str, Any],
    ) -> RawProbe:
        endpoint = task.endpoint
        if endpoint is None:
            raise ValueError("AttackTask.endpoint must be loaded before execute()")

        worker_id = self._worker_id()
        allowed_domains = self._resolve_allowed_domains(task)
        cookies = self._to_httpx_cookies(session.cookies)
        carried_values: dict[str, Any] = {}
        chain_entries: list[dict[str, Any]] = []

        last_request: httpx.Request | None = None
        last_response: httpx.Response | None = None
        last_latency_ms = 0

        async with httpx.AsyncClient(cookies=cookies, follow_redirects=True) as client:
            for idx, step in enumerate(steps, start=1):
                if not isinstance(step, dict):
                    continue

                method = str(step.get("method") or endpoint.method).upper()
                step_url = str(step.get("url_pattern") or endpoint.url_pattern)
                url = self._apply_value_templates(step_url, carried_values)
                probe_type = step.get("probe_type")

                domain = self._extract_request_domain(url)
                if not self._is_domain_allowed(domain, allowed_domains):
                    raise GuardrailViolation(
                        f"Out-of-scope target domain '{domain}' for task {task.id}; allowed domains: {sorted(allowed_domains)}"
                    )
                if (
                    self._rate_limiter.production_safe_mode
                    and not self._rate_limiter.allow_mutating_methods
                    and method in DomainRateLimiter.MUTATING_METHODS
                ):
                    raise GuardrailViolation(f"Mutating method '{method}' blocked in production-safe mode")

                await self._enforce_rate_limit(scan_id=str(task.scan_id), domain=domain, method=method, worker_id=worker_id)
                await self._apply_timing_profile(hypothesis_config.get("timing_profile"))

                headers = self._build_probe_headers(session=session, probe_type=probe_type)
                extra_headers = step.get("headers")
                if isinstance(extra_headers, dict):
                    for key, value in extra_headers.items():
                        if isinstance(key, str):
                            headers[key] = self._apply_value_templates(str(value), carried_values)
                for key, value in carried_values.items():
                    header_name = f"X-Chain-{key}"
                    headers.setdefault(header_name, str(value))

                params_payload: dict[str, Any] = {}
                step_params = step.get("params")
                if isinstance(step_params, dict):
                    for key, value in step_params.items():
                        if isinstance(key, str):
                            params_payload[key] = self._apply_value_templates(str(value), carried_values)
                for key, value in carried_values.items():
                    params_payload.setdefault(key, str(value))

                request, response, latency_ms = await self._send_request(
                    client=client,
                    method=method,
                    url=url,
                    headers=headers,
                    params=params_payload or None,
                )
                last_request = request
                last_response = response
                last_latency_ms = latency_ms

                chain_entry = {"chain_step": idx, "probe_type": probe_type}
                if probe_type == "replay":
                    chain_entry["reused_token"] = True
                mutation_class = self._mutation_class_for_probe_type(probe_type)
                if mutation_class is not None:
                    chain_entry["mutation_class"] = mutation_class
                chain_entries.append(chain_entry)
                logger.info(
                    "attack_probe_chain_entry",
                    attack_task_id=str(task.id),
                    entry=self._strip_sensitive(chain_entry),
                )

                extract_spec = step.get("extract")
                if isinstance(extract_spec, dict):
                    response_json = self._response_json(response)
                    for key, path in extract_spec.items():
                        if not isinstance(key, str) or not isinstance(path, str):
                            continue
                        extracted = self._extract_json_path(response_json, path)
                        if extracted is not None:
                            carried_values[key] = extracted

        if last_request is None or last_response is None:
            raise GuardrailViolation(f"No executable chain step found for task {task.id}")

        raw_probe = self._build_raw_probe(
            task=task,
            worker_id=worker_id,
            request=last_request,
            response=last_response,
            latency_ms=last_latency_ms,
        )
        await self._publish_evidence(
            task.scan_id,
            raw_probe,
            metadata={
                "chain_id": f"{task.id}_chain",
                "chain_entries": json.dumps(chain_entries),
            },
        )
        return raw_probe

    def _response_json(self, response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            return {}

    def _extract_json_path(self, payload: Any, path: str) -> Any:
        current: Any = payload
        for part in path.split("."):
            if isinstance(current, dict):
                if part not in current:
                    return None
                current = current[part]
                continue
            if isinstance(current, list):
                try:
                    index = int(part)
                except ValueError:
                    return None
                if index < 0 or index >= len(current):
                    return None
                current = current[index]
                continue
            return None
        return current

    def _apply_value_templates(self, value: str, carried_values: dict[str, Any]) -> str:
        resolved = value
        for key, item in carried_values.items():
            resolved = resolved.replace("{" + key + "}", str(item))
        return resolved

    def _to_httpx_cookies(self, cookies: list[dict[str, Any]]) -> httpx.Cookies:
        jar = httpx.Cookies()
        for cookie in cookies:
            name = cookie.get("name")
            value = cookie.get("value")
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            jar.set(
                name,
                value,
                domain=cookie.get("domain"),
                path=cookie.get("path", "/"),
            )
        return jar

    def _decode_request_body(self, body: bytes | None) -> str:
        if not body:
            return ""
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return body.decode("utf-8", errors="replace")

    def _worker_id(self) -> str:
        hostname = os.getenv("HOSTNAME", "worker")
        pid = os.getpid()
        return f"{hostname}:{pid}"

    def _save_state_snapshot(
        self,
        task: AttackTask,
        status: str,
        response_status_code: int | None = None,
    ) -> None:
        scan_id = str(task.scan_id)
        step_id = str(task.id)
        version_key = (scan_id, step_id)
        next_version = self._snapshot_versions.get(version_key, 0) + 1
        self._snapshot_versions[version_key] = next_version

        state_dict: dict[str, Any] = {
            "task_id": str(task.id),
            "status": status,
            "response_status_code": response_status_code,
        }

        self._state_store.save_snapshot(
            StateSnapshot(
                scan_id=scan_id,
                step_id=step_id,
                timestamp=datetime.now(UTC),
                state_dict=state_dict,
                version=next_version,
            )
        )
