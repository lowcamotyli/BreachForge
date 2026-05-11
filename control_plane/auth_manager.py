from __future__ import annotations

import asyncio
import contextlib
import json
import os
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse
from enum import Enum
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Literal, TypeAlias
from uuid import UUID

import httpx
import structlog
from playwright.async_api import Page, async_playwright
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from api.models.requests import AuthContextCreate
from storage.db.models import AuthContext, Scan, ScanStatus

try:
    from storage.db.encryption import EncryptedBlob, EnvelopeEncryption
except ImportError:
    EncryptedBlob = None  # type: ignore[assignment,misc]
    EnvelopeEncryption = None  # type: ignore[assignment,misc]

AUTH_HEALTH_CHECK_INTERVAL_S = int(os.getenv("AUTH_HEALTH_CHECK_INTERVAL_S", "300"))

REDACTED_FIELDS = {"authorization", "cookie", "password", "token"}

logger = structlog.get_logger(__name__)

__all__ = [
    "AuthManager",
    "BrowserSessionImporter",
    "IdentityRole",
    "IdentityContext",
    "IdentityProfile",
    "IdentityMatrix",
    "SessionSnapshot",
]

AUTH_STATE_VALUES = {"active", "expired", "none"}


@dataclass(slots=True)
class IdentityProfile:
    name: str
    role: str | None
    tenant: str | None
    auth_state: Literal["active", "expired", "none"]
    privilege_hint: str | None
    session_ref: str | None

    def __post_init__(self) -> None:
        if self.auth_state not in AUTH_STATE_VALUES:
            raise ValueError(f"Invalid auth_state: {self.auth_state}")


IdentityMatrix: TypeAlias = dict[str, IdentityProfile]


class AuthPauseRequiredError(RuntimeError):
    pass


@dataclass(slots=True)
class SessionSnapshot:
    scan_id: UUID | None = None
    cookies: list[dict[str, Any]] | dict[str, str] = None
    auth_headers: dict[str, str] = None
    csrf_tokens: dict[str, str] = None
    captured_at: datetime = None
    expires_at: datetime | None = None
    url: str = ""
    domain: str = ""
    local_storage: dict[str, str] = None
    session_storage: dict[str, str] = None
    cookie_count: int = 0
    has_auth_token: bool = False

    def __post_init__(self) -> None:
        if self.cookies is None:
            self.cookies = []
        if self.auth_headers is None:
            self.auth_headers = {}
        if self.csrf_tokens is None:
            self.csrf_tokens = {}
        if self.captured_at is None:
            self.captured_at = datetime.now(UTC)
        if self.local_storage is None:
            self.local_storage = {}
        if self.session_storage is None:
            self.session_storage = {}


class BrowserSessionImporter:
    async def import_from_browser(self, url: str, wait_seconds: int = 5) -> SessionSnapshot:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=False)
            context = await browser.new_context()
            page = await context.new_page()

            await page.goto(url)
            await page.wait_for_timeout(max(wait_seconds, 0) * 1000)

            cookies_raw = await context.cookies()
            local_storage_raw = await page.evaluate(
                """
                () => {
                    const out = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        if (!key) continue;
                        const value = localStorage.getItem(key);
                        if (value !== null) out[key] = value;
                    }
                    return out;
                }
                """
            )
            session_storage_raw = await page.evaluate(
                """
                () => {
                    const out = {};
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        if (!key) continue;
                        const value = sessionStorage.getItem(key);
                        if (value !== null) out[key] = value;
                    }
                    return out;
                }
                """
            )

            await browser.close()

        cookie_map: dict[str, str] = {}
        for cookie in cookies_raw:
            name = cookie.get("name")
            value = cookie.get("value")
            if isinstance(name, str) and isinstance(value, str):
                cookie_map[name] = value

        local_storage: dict[str, str] = {}
        if isinstance(local_storage_raw, dict):
            for key, value in local_storage_raw.items():
                if isinstance(key, str) and isinstance(value, str):
                    local_storage[key] = value

        session_storage: dict[str, str] = {}
        if isinstance(session_storage_raw, dict):
            for key, value in session_storage_raw.items():
                if isinstance(key, str) and isinstance(value, str):
                    session_storage[key] = value

        has_auth_token = any(
            any(marker in cookie_name.lower() for marker in ("session", "token", "auth", "jwt", "sid"))
            for cookie_name in cookie_map
        )

        parsed = urlparse(url)
        return SessionSnapshot(
            scan_id=None,
            url=url,
            domain=parsed.netloc,
            cookies=cookie_map,
            local_storage=local_storage,
            session_storage=session_storage,
            auth_headers={},
            csrf_tokens={},
            cookie_count=len(cookie_map),
            has_auth_token=has_auth_token,
            captured_at=datetime.now(UTC),
            expires_at=None,
        )

    async def check_session_health(self, snapshot: SessionSnapshot, test_endpoints: list[str]) -> dict[str, bool | str]:
        if not test_endpoints:
            return {"warning": "no_test_endpoints_provided"}

        cookies = snapshot.cookies if isinstance(snapshot.cookies, dict) else {}
        results: dict[str, bool | str] = {}
        unauthorized_count = 0

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for endpoint in test_endpoints:
                try:
                    response = await client.get(endpoint, cookies=cookies)
                except httpx.HTTPError:
                    results[endpoint] = False
                    continue

                is_authenticated = response.status_code not in {401, 403}
                results[endpoint] = is_authenticated
                if response.status_code in {401, 403}:
                    unauthorized_count += 1

        if unauthorized_count == len(test_endpoints):
            results["warning"] = "all_test_endpoints_returned_401_or_403_scan_continues_unauthenticated"

        return results


class IdentityRole(str, Enum):
    anon = "anon"
    user = "user"
    admin = "admin"
    tenant_a = "tenant_a"
    tenant_b = "tenant_b"


@dataclass(slots=True)
class IdentityContext:
    scan_id: UUID
    role: IdentityRole
    cookies: list[dict[str, Any]]
    auth_headers: dict[str, str]
    csrf_tokens: dict[str, str]
    captured_at: datetime
    expires_at: datetime | None = None
    active: bool = True

    def to_session_snapshot(self) -> SessionSnapshot:
        return SessionSnapshot(
            scan_id=self.scan_id,
            cookies=deepcopy(self.cookies),
            auth_headers=deepcopy(self.auth_headers),
            csrf_tokens=deepcopy(self.csrf_tokens),
            captured_at=self.captured_at,
            expires_at=self.expires_at,
        )


class AuthManager:
    def __init__(
        self,
        scan_id: UUID,
        session_factory: async_sessionmaker[AsyncSession],
        pause_scan: Callable[[UUID, str], Awaitable[None]],
        authenticated_probe_url: str | None = None,
        encryption_service: EnvelopeEncryption | None = None,
    ) -> None:
        self._scan_id = scan_id
        self._session_factory = session_factory
        self._pause_scan = pause_scan
        self._authenticated_probe_url = authenticated_probe_url
        self._encryption_service = encryption_service

        self._lock = asyncio.Lock()
        self._active = True
        self._session_snapshot: SessionSnapshot | None = None
        self._identity_contexts: dict[IdentityRole, IdentityContext] = {}
        self._auth_type: str = "none"
        self._auth_input: AuthContextCreate | None = None
        self._health_task: asyncio.Task[None] | None = None

    async def bootstrap(self, auth_input: AuthContextCreate) -> AuthContext:
        try:
            if auth_input.type == "session":
                snapshot = self._from_cookies(auth_input)
            elif auth_input.type == "token":
                snapshot = self._from_bearer(auth_input)
            elif auth_input.type == "credential":
                snapshot = await self._playwright_login(auth_input)
            elif auth_input.type == "none":
                snapshot = self._empty_snapshot()
            else:
                raise ValueError(f"Unsupported auth type: {auth_input.type}")

            await self._set_snapshot(snapshot, auth_input)
            await self._probe_or_pause("auth_bootstrap_probe_failed")
            return await self._upsert_auth_context(snapshot, auth_input.type)
        except AuthPauseRequiredError:
            raise
        except Exception as exc:
            await self._pause_with_error(f"auth_bootstrap_failed:{type(exc).__name__}:{exc}")
            raise

    async def close(self) -> None:
        self._active = False
        if self._health_task is not None:
            self._health_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_task
        try:
            await self.purge_credentials_if_terminal()
        except Exception:
            logger.exception("auth_context_purge_failed", scan_id=str(self._scan_id))

    async def purge_credentials_if_terminal(self) -> None:
        async with self._session_factory() as session:
            scan_result = await session.execute(select(Scan).where(Scan.id == self._scan_id))
            scan = scan_result.scalar_one_or_none()
            if scan is None or scan.status not in {ScanStatus.complete, ScanStatus.failed}:
                return

            auth_result = await session.execute(select(AuthContext).where(AuthContext.scan_id == self._scan_id))
            auth_context = auth_result.scalar_one_or_none()
            if auth_context is None:
                return

            auth_context.session_snapshot = {
                "scan_id": str(self._scan_id),
                "purged": True,
                "purged_at": datetime.now(UTC).isoformat(),
            }
            await session.commit()

        async with self._lock:
            if self._session_snapshot is not None:
                self._session_snapshot.cookies = []
                self._session_snapshot.auth_headers = {}
                self._session_snapshot.csrf_tokens = {}
            for identity in self._identity_contexts.values():
                identity.cookies = []
                identity.auth_headers = {}
                identity.csrf_tokens = {}
            if self._auth_input is not None:
                self._auth_input.credentials = None
                self._auth_input.cookies = None
                self._auth_input.bearer_token = None

    async def get_session_snapshot(self, scan_id: UUID) -> SessionSnapshot:
        if scan_id != self._scan_id:
            raise ValueError("Scan ID mismatch for requested session snapshot")

        async with self._lock:
            if self._session_snapshot is None:
                raise RuntimeError("Session snapshot is not initialized")
            return deepcopy(self._session_snapshot)

    async def health_check(self) -> bool:
        try:
            ok = await self._probe_authenticated_endpoint()
        except Exception:
            await self._pause_with_error("auth_expired:health_check_failed")
            return False

        if ok:
            return True

        try:
            refreshed = await self._attempt_refresh()
        except Exception:
            await self._pause_with_error("auth_expired:refresh_failed")
            return False

        if refreshed:
            return True

        await self._pause_with_error("auth_expired")
        return False

    async def get_identity_context(self, scan_id: UUID, role: IdentityRole | str) -> IdentityContext:
        if scan_id != self._scan_id:
            raise ValueError("Scan ID mismatch for requested identity context")

        requested_role = self._coerce_identity_role(role)
        async with self._lock:
            if self._session_snapshot is None:
                raise RuntimeError("Session snapshot is not initialized")

            if not self._identity_contexts:
                self._identity_contexts = self._build_identity_contexts(self._session_snapshot)

            identity_context = self._identity_contexts.get(requested_role)
            if identity_context is None:
                raise RuntimeError(f"Identity context is not initialized for role={requested_role.value}")
            return deepcopy(identity_context)

    async def list_active_identities(self, scan_id: UUID) -> list[IdentityContext]:
        if scan_id != self._scan_id:
            raise ValueError("Scan ID mismatch for requested identity contexts")

        async with self._lock:
            if self._session_snapshot is None:
                raise RuntimeError("Session snapshot is not initialized")

            if not self._identity_contexts:
                self._identity_contexts = self._build_identity_contexts(self._session_snapshot)

            self._ensure_minimum_active_identities()
            active = [deepcopy(identity) for identity in self._identity_contexts.values() if identity.active]
            return active

    async def _set_snapshot(self, snapshot: SessionSnapshot, auth_input: AuthContextCreate) -> None:
        async with self._lock:
            self._session_snapshot = deepcopy(snapshot)
            self._identity_contexts = self._build_identity_contexts(snapshot)
            self._auth_type = auth_input.type
            self._auth_input = auth_input.model_copy(deep=True)

        if self._health_task is None or self._health_task.done():
            self._health_task = asyncio.create_task(self._health_loop())

    def _from_cookies(self, auth_input: AuthContextCreate) -> SessionSnapshot:
        cookies = deepcopy(auth_input.cookies or [])
        expires_at = self._infer_expiry_from_cookies(cookies)
        csrf_tokens = self._csrf_tokens_from_cookies(cookies)
        return SessionSnapshot(
            scan_id=self._scan_id,
            cookies=cookies,
            auth_headers={},
            csrf_tokens=csrf_tokens,
            captured_at=datetime.now(UTC),
            expires_at=expires_at,
        )

    def _from_bearer(self, auth_input: AuthContextCreate) -> SessionSnapshot:
        if not auth_input.bearer_token:
            raise ValueError("Missing bearer token for token auth type")
        return SessionSnapshot(
            scan_id=self._scan_id,
            cookies=[],
            auth_headers={"Authorization": f"Bearer {auth_input.bearer_token}"},
            csrf_tokens={},
            captured_at=datetime.now(UTC),
            expires_at=None,
        )

    async def _playwright_login(self, auth_input: AuthContextCreate) -> SessionSnapshot:
        login_recipe = auth_input.login_recipe or {}
        steps = login_recipe.get("steps")
        if not isinstance(steps, list) or not steps:
            raise ValueError("Credential auth requires login_recipe.steps")

        credentials = auth_input.credentials or {}
        auth_headers: dict[str, str] = {}
        csrf_tokens: dict[str, str] = {}

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            await self._run_login_steps(page, steps, credentials)
            await self._capture_dynamic_auth(page, auth_headers, csrf_tokens)
            cookies = await context.cookies()

            await browser.close()

        expires_at = self._infer_expiry_from_cookies(cookies)
        return SessionSnapshot(
            scan_id=self._scan_id,
            cookies=cookies,
            auth_headers=auth_headers,
            csrf_tokens=csrf_tokens,
            captured_at=datetime.now(UTC),
            expires_at=expires_at,
        )

    async def _run_login_steps(self, page: Page, steps: list[dict[str, Any]], credentials: dict[str, str]) -> None:
        for index, step in enumerate(steps):
            action = step.get("action")
            if action == "navigate":
                url = step.get("url")
                if not isinstance(url, str):
                    raise ValueError(f"Invalid navigate step at index {index}")
                await page.goto(url)
                continue

            if action == "fill":
                selector = step.get("selector")
                value = self._resolve_step_value(step.get("value", ""), credentials)
                if not isinstance(selector, str):
                    raise ValueError(f"Invalid fill selector at index {index}")
                await page.fill(selector, value)
                continue

            if action == "click":
                selector = step.get("selector")
                if not isinstance(selector, str):
                    raise ValueError(f"Invalid click selector at index {index}")
                await page.click(selector)
                continue

            if action == "wait_for_url":
                pattern = step.get("pattern")
                if not isinstance(pattern, str):
                    raise ValueError(f"Invalid wait_for_url pattern at index {index}")
                await page.wait_for_url(f"**{pattern}**")
                continue

            raise ValueError(f"Unsupported login_recipe action at index {index}: {action}")

    async def _capture_dynamic_auth(
        self,
        page: Page,
        auth_headers: dict[str, str],
        csrf_tokens: dict[str, str],
    ) -> None:
        local_storage = await page.evaluate(
            """
            () => {
                const data = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (!key) continue;
                    data[key] = localStorage.getItem(key);
                }
                return data;
            }
            """
        )

        if not isinstance(local_storage, dict):
            return

        for key, value in local_storage.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            key_lower = key.lower()
            if "csrf" in key_lower:
                csrf_tokens[key] = value
            if "token" in key_lower and "Authorization" not in auth_headers:
                auth_headers["Authorization"] = f"Bearer {value}"

    async def _health_loop(self) -> None:
        while self._active:
            await asyncio.sleep(AUTH_HEALTH_CHECK_INTERVAL_S)
            try:
                ok = await self._probe_authenticated_endpoint()
                if ok:
                    continue

                refreshed = await self._attempt_refresh()
                if not refreshed:
                    await self._pause_with_error("auth_expired")
                    return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await self._pause_with_error(f"auth_health_check_failed:{type(exc).__name__}:{exc}")
                return

    async def _probe_or_pause(self, error_code: str) -> None:
        ok = await self._probe_authenticated_endpoint()
        if ok:
            return
        await self._pause_with_error(error_code)
        raise AuthPauseRequiredError(error_code)

    async def _probe_authenticated_endpoint(self) -> bool:
        snapshot = await self.get_session_snapshot(self._scan_id)
        if self._auth_type == "none":
            return True
        if self._authenticated_probe_url is None:
            return bool(snapshot.cookies or snapshot.auth_headers)

        headers = self._build_probe_headers(snapshot)
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                response = await client.get(self._authenticated_probe_url, headers=headers)
        except httpx.HTTPError:
            return False

        if response.status_code in {401, 403}:
            return False
        return 200 <= response.status_code < 400

    async def _attempt_refresh(self) -> bool:
        async with self._lock:
            auth_input = self._auth_input.model_copy(deep=True) if self._auth_input is not None else None

        if auth_input is None or auth_input.type == "none":
            return False

        if auth_input.type == "credential":
            snapshot = await self._playwright_login(auth_input)
        elif auth_input.type == "session":
            snapshot = self._from_cookies(auth_input)
        elif auth_input.type == "token":
            snapshot = self._from_bearer(auth_input)
        else:
            return False

        await self._set_snapshot(snapshot, auth_input)
        await self._upsert_auth_context(snapshot, auth_input.type)
        return await self._probe_authenticated_endpoint()

    async def _upsert_auth_context(self, snapshot: SessionSnapshot, auth_type: str) -> AuthContext:
        async with self._lock:
            auth_input = self._auth_input.model_copy(deep=True) if self._auth_input is not None else None

        payload = {
            "scan_id": str(snapshot.scan_id),
            "credentials": self._encrypt_snapshot_field(auth_input.credentials) if auth_input else None,
            "cookies": self._encrypt_snapshot_field(snapshot.cookies),
            "bearer_token": self._encrypt_snapshot_field(auth_input.bearer_token) if auth_input else None,
            "login_recipe": auth_input.login_recipe if auth_input else None,
            "auth_headers": self._encrypt_snapshot_field(snapshot.auth_headers),
            "csrf_tokens": self._encrypt_snapshot_field(snapshot.csrf_tokens),
            "captured_at": snapshot.captured_at.isoformat(),
            "expires_at": snapshot.expires_at.isoformat() if snapshot.expires_at else None,
        }

        async with self._session_factory() as session:
            result = await session.execute(select(AuthContext).where(AuthContext.scan_id == self._scan_id))
            auth_context = result.scalar_one_or_none()

            if auth_context is None:
                auth_context = AuthContext(
                    scan_id=self._scan_id,
                    type=auth_type,
                    session_snapshot=payload,
                    health={"status": "healthy", "updated_at": datetime.now(UTC).isoformat()},
                )
                session.add(auth_context)
            else:
                auth_context.type = auth_type
                auth_context.session_snapshot = payload
                auth_context.health = {"status": "healthy", "updated_at": datetime.now(UTC).isoformat()}

            scan_result = await session.execute(select(Scan).where(Scan.id == self._scan_id))
            scan = scan_result.scalar_one_or_none()
            if scan is not None:
                scan.auth_context_ref = auth_context

            await session.commit()
            await session.refresh(auth_context)
            return auth_context

    def _encrypt_snapshot_field(self, value: Any) -> dict[str, str]:
        plaintext = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
        encryption = self._encryption_service or EnvelopeEncryption()
        blob = encryption.encrypt_credential(plaintext, self._scan_id)
        return {
            "_encrypted": "kms_envelope_v1",
            "encrypted_data_key": blob.encrypted_data_key,
            "ciphertext": blob.ciphertext,
        }

    async def _pause_with_error(self, reason: str) -> None:
        safe_reason = self._redact_sensitive_text(reason)
        log_context = self._sanitize_log_data(
            {
                "scan_id": str(self._scan_id),
                "reason": safe_reason,
                "auth_type": self._auth_type,
                "auth_input": self._auth_input.model_dump() if self._auth_input else None,
            }
        )
        logger.error("auth_manager_pausing_scan", **log_context)

        await self._pause_scan(self._scan_id, safe_reason)
        await self._mark_auth_context_unhealthy(safe_reason)

    async def _mark_auth_context_unhealthy(self, reason: str) -> None:
        async with self._session_factory() as session:
            result = await session.execute(select(AuthContext).where(AuthContext.scan_id == self._scan_id))
            auth_context = result.scalar_one_or_none()
            if auth_context is None:
                return

            auth_context.health = {
                "status": "unhealthy",
                "updated_at": datetime.now(UTC).isoformat(),
                "error": reason,
            }

            await session.commit()

    def _build_probe_headers(self, snapshot: SessionSnapshot) -> dict[str, str]:
        headers = deepcopy(snapshot.auth_headers)
        if snapshot.cookies:
            cookie_header = "; ".join(
                f"{cookie.get('name', '')}={cookie.get('value', '')}" for cookie in snapshot.cookies if cookie.get("name")
            )
            if cookie_header:
                headers["Cookie"] = cookie_header
        headers.update(snapshot.csrf_tokens)
        return headers

    def _empty_snapshot(self) -> SessionSnapshot:
        return SessionSnapshot(
            scan_id=self._scan_id,
            cookies=[],
            auth_headers={},
            csrf_tokens={},
            captured_at=datetime.now(UTC),
            expires_at=None,
        )

    def _infer_expiry_from_cookies(self, cookies: list[dict[str, Any]]) -> datetime | None:
        expiries: list[datetime] = []
        for cookie in cookies:
            expires_value = cookie.get("expires")
            if isinstance(expires_value, (int, float)) and expires_value > 0:
                expiries.append(datetime.fromtimestamp(expires_value, tz=UTC))

        if not expiries:
            return None
        return min(expiries)

    def _csrf_tokens_from_cookies(self, cookies: list[dict[str, Any]]) -> dict[str, str]:
        tokens: dict[str, str] = {}
        for cookie in cookies:
            name = cookie.get("name")
            value = cookie.get("value")
            if isinstance(name, str) and isinstance(value, str) and "csrf" in name.lower():
                tokens[name] = value
        return tokens

    def _resolve_step_value(self, raw_value: Any, credentials: dict[str, str]) -> str:
        if not isinstance(raw_value, str):
            return ""
        resolved = raw_value
        for key, value in credentials.items():
            placeholder = "{" + key + "}"
            resolved = resolved.replace(placeholder, value)
        return resolved

    def _sanitize_log_data(self, data: Any) -> Any:
        if isinstance(data, dict):
            sanitized: dict[str, Any] = {}
            for key, value in data.items():
                key_lower = str(key).lower()
                if any(secret in key_lower for secret in REDACTED_FIELDS):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self._sanitize_log_data(value)
            return sanitized

        if isinstance(data, list):
            return [self._sanitize_log_data(item) for item in data]

        return data

    def _redact_sensitive_text(self, value: str) -> str:
        lowered = value.lower()
        if any(secret in lowered for secret in REDACTED_FIELDS):
            return "[REDACTED]"
        return value

    def _coerce_identity_role(self, role: IdentityRole | str) -> IdentityRole:
        if isinstance(role, IdentityRole):
            return role
        try:
            return IdentityRole(role)
        except ValueError as exc:
            raise ValueError(f"Unsupported identity role: {role}") from exc

    def _build_identity_contexts(self, snapshot: SessionSnapshot) -> dict[IdentityRole, IdentityContext]:
        base_auth_headers = deepcopy(snapshot.auth_headers)
        base_csrf_tokens = deepcopy(snapshot.csrf_tokens)
        base_cookies = deepcopy(snapshot.cookies)

        identity_contexts: dict[IdentityRole, IdentityContext] = {
            IdentityRole.anon: IdentityContext(
                scan_id=self._scan_id,
                role=IdentityRole.anon,
                cookies=[],
                auth_headers={},
                csrf_tokens={},
                captured_at=snapshot.captured_at,
                expires_at=None,
                active=True,
            ),
            IdentityRole.user: IdentityContext(
                scan_id=self._scan_id,
                role=IdentityRole.user,
                cookies=deepcopy(base_cookies),
                auth_headers=deepcopy(base_auth_headers),
                csrf_tokens=deepcopy(base_csrf_tokens),
                captured_at=snapshot.captured_at,
                expires_at=snapshot.expires_at,
                active=True,
            ),
            IdentityRole.admin: IdentityContext(
                scan_id=self._scan_id,
                role=IdentityRole.admin,
                cookies=deepcopy(base_cookies),
                auth_headers={**deepcopy(base_auth_headers), "X-Identity-Role": IdentityRole.admin.value},
                csrf_tokens=deepcopy(base_csrf_tokens),
                captured_at=snapshot.captured_at,
                expires_at=snapshot.expires_at,
                active=True,
            ),
            IdentityRole.tenant_a: IdentityContext(
                scan_id=self._scan_id,
                role=IdentityRole.tenant_a,
                cookies=deepcopy(base_cookies),
                auth_headers={
                    **deepcopy(base_auth_headers),
                    "X-Identity-Role": IdentityRole.user.value,
                    "X-Tenant-Context": IdentityRole.tenant_a.value,
                },
                csrf_tokens=deepcopy(base_csrf_tokens),
                captured_at=snapshot.captured_at,
                expires_at=snapshot.expires_at,
                active=True,
            ),
            IdentityRole.tenant_b: IdentityContext(
                scan_id=self._scan_id,
                role=IdentityRole.tenant_b,
                cookies=deepcopy(base_cookies),
                auth_headers={
                    **deepcopy(base_auth_headers),
                    "X-Identity-Role": IdentityRole.user.value,
                    "X-Tenant-Context": IdentityRole.tenant_b.value,
                },
                csrf_tokens=deepcopy(base_csrf_tokens),
                captured_at=snapshot.captured_at,
                expires_at=snapshot.expires_at,
                active=True,
            ),
        }
        return identity_contexts

    def _ensure_minimum_active_identities(self) -> None:
        active_count = sum(1 for identity in self._identity_contexts.values() if identity.active)
        if active_count >= 3:
            return

        for role in (IdentityRole.anon, IdentityRole.user, IdentityRole.admin, IdentityRole.tenant_a, IdentityRole.tenant_b):
            context = self._identity_contexts.get(role)
            if context is None:
                continue
            if not context.active:
                context.active = True
                active_count += 1
            if active_count >= 3:
                return


async def default_pause_scan(scan_id: UUID, reason: str) -> None:
    from storage.db.session import AsyncSessionLocal

    safe_reason = "[REDACTED]" if any(token in reason.lower() for token in REDACTED_FIELDS) else reason
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan is not None:
            scan.status = ScanStatus.paused
            scan.phase = f"paused:{safe_reason[:57]}"
            await session.commit()

    logger.error("scan_pause_requested", scan_id=str(scan_id), reason=safe_reason)


async def _mark_scan_recon_started(scan_id: UUID) -> None:
    from storage.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan is None:
            raise LookupError(f"Scan not found for recon transition: {scan_id}")

        scan.status = ScanStatus.running
        scan.phase = "recon"
        await session.commit()


def _decrypt_snapshot_field(value: Any, scan_id: UUID) -> Any:
    if not isinstance(value, dict):
        return value

    if value.get("_encrypted") != "kms_envelope_v1":
        return value

    encrypted_data_key = value.get("encrypted_data_key")
    ciphertext = value.get("ciphertext")
    if not isinstance(encrypted_data_key, str) or not isinstance(ciphertext, str):
        raise ValueError("Invalid encrypted snapshot payload")

    encryption = EnvelopeEncryption()
    decrypted = encryption.decrypt_credential(
        EncryptedBlob(encrypted_data_key=encrypted_data_key, ciphertext=ciphertext),
        scan_id,
    )

    try:
        return json.loads(decrypted)
    except json.JSONDecodeError:
        return decrypted


def _build_auth_input_from_snapshot(auth_type: str, snapshot: dict[str, Any], scan_id: UUID) -> AuthContextCreate:
    credentials = _decrypt_snapshot_field(snapshot.get("credentials"), scan_id)
    cookies = _decrypt_snapshot_field(snapshot.get("cookies"), scan_id)
    bearer_token = _decrypt_snapshot_field(snapshot.get("bearer_token"), scan_id)
    login_recipe = snapshot.get("login_recipe")

    return AuthContextCreate(
        type=auth_type,
        credentials=credentials if isinstance(credentials, dict) else None,
        cookies=cookies if isinstance(cookies, list) else None,
        bearer_token=bearer_token if isinstance(bearer_token, str) else None,
        login_recipe=login_recipe if isinstance(login_recipe, dict) else None,
    )


async def purge_scan_credentials(scan_id: UUID) -> None:
    from storage.db.session import AsyncSessionLocal

    manager = AuthManager(scan_id, AsyncSessionLocal, default_pause_scan)
    await manager.purge_credentials_if_terminal()


def bootstrap_auth_context(scan_id: str, auth_context_id: str | None = None) -> None:
    asyncio.run(_bootstrap_auth_context_async(scan_id=scan_id, auth_context_id=auth_context_id))


async def _bootstrap_auth_context_async(scan_id: str, auth_context_id: str | None = None) -> None:
    from storage.db.session import AsyncSessionLocal

    scan_uuid = UUID(scan_id)
    auth_context_uuid = UUID(auth_context_id) if auth_context_id else None

    async with AsyncSessionLocal() as db:
        stmt = select(AuthContext).where(AuthContext.scan_id == scan_uuid)
        if auth_context_uuid is not None:
            stmt = stmt.where(AuthContext.id == auth_context_uuid)
        result = await db.execute(stmt)
        auth_context = result.scalar_one_or_none()
        if auth_context is None:
            raise LookupError(f"Auth context not found for scan {scan_id}")

    snapshot = auth_context.session_snapshot if isinstance(auth_context.session_snapshot, dict) else {}
    auth_input = _build_auth_input_from_snapshot(auth_context.type, snapshot, scan_uuid)

    manager = AuthManager(scan_uuid, AsyncSessionLocal, default_pause_scan)
    try:
        await manager.bootstrap(auth_input)
    finally:
        await manager.close()

    await _mark_scan_recon_started(scan_uuid)

    try:
        from redis import Redis
        from rq import Queue

        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            raise RuntimeError("REDIS_URL is not configured")
        connection = Redis.from_url(redis_url)
        queue_name = os.getenv("RQ_RECON_QUEUE", "recon")
        queue = Queue(name=queue_name, connection=connection)
        queue.enqueue("execution_plane.crawler.engine.run_crawler", str(scan_uuid))
    except Exception as exc:
        logger.exception("recon_enqueue_failed", scan_id=str(scan_uuid), error=str(exc))
