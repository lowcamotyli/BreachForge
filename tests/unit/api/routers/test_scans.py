from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.models.requests import AuthContextCreate, ScanCreate
from api.routers import scans as scans_module
from control_plane.orchestrator import PreflightResult
from storage.db.models import AuthContext, Scan, ScanStatus, Target


class _FakeResult:
    def __init__(self, item: object | None) -> None:
        self._item = item

    def scalar_one_or_none(self) -> object | None:
        return self._item


class _PreflightDb:
    def __init__(self, *, scan: Scan | None, target: Target | None, auth_context: AuthContext | None) -> None:
        self._scan = scan
        self._target = target
        self._auth_context = auth_context

    async def execute(self, statement: object) -> _FakeResult:
        entity = statement.column_descriptions[0]["entity"]
        if entity is Scan:
            return _FakeResult(self._scan)
        if entity is Target:
            return _FakeResult(self._target)
        if entity is AuthContext:
            return _FakeResult(self._auth_context)
        return _FakeResult(None)


def _scans_client() -> TestClient:
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(scans_module.router, prefix="/scans")
    return TestClient(app)


def test_build_session_snapshot_encrypts_sensitive_auth_material(monkeypatch) -> None:
    encrypted_payloads: list[str] = []

    class _FakeEncryption:
        def encrypt_credential(self, plaintext: str, scan_id):
            encrypted_payloads.append(plaintext)
            return SimpleNamespace(encrypted_data_key="key", ciphertext="cipher")

    monkeypatch.setattr(scans_module, "EnvelopeEncryption", _FakeEncryption)

    payload = ScanCreate(
        target_url="https://app.example.com",
        auth_context=AuthContextCreate(
            type="credential",
            credentials={"username": "analyst", "password": "secret-password"},
            cookies=[{"name": "sessionid", "value": "cookie-secret"}],
            bearer_token="secret-token",
            login_recipe={"steps": [{"action": "navigate", "url": "https://app.example.com/login"}]},
        ),
    )

    snapshot = scans_module._build_session_snapshot(payload, uuid4())

    assert snapshot["credentials"]["_encrypted"] == "kms_envelope_v1"
    assert snapshot["cookies"]["_encrypted"] == "kms_envelope_v1"
    assert snapshot["bearer_token"]["_encrypted"] == "kms_envelope_v1"
    assert json.dumps(snapshot).find("secret-password") == -1
    assert json.dumps(snapshot).find("secret-token") == -1
    assert json.dumps(snapshot).find("cookie-secret") == -1
    assert len(encrypted_payloads) == 3


@pytest.mark.parametrize(
    ("preflight_status", "expected_score"),
    [
        ("ok", 1.0),
        ("degraded", 0.5),
        ("failed", 0.0),
    ],
)
def test_get_auth_readiness_returns_score_for_status(
    monkeypatch: pytest.MonkeyPatch,
    preflight_status: str,
    expected_score: float,
) -> None:
    async def _preflight(scan_config: object) -> PreflightResult:
        assert getattr(scan_config, "target_url") == "https://app.example.com"
        return PreflightResult(
            status=preflight_status,
            failures=[] if preflight_status == "ok" else ["invalid_session"],
            missing_roles=[],
            missing_tenants=[],
            csrf_status="ok",
        )

    monkeypatch.setattr(scans_module, "preflight_auth_check", _preflight)

    response = _scans_client().get(
        "/scans/auth/readiness",
        params={
            "target_url": "https://app.example.com",
            "bearer_token": "secret-token-value",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == preflight_status
    assert payload["readiness_score"] == expected_score
    assert payload["failing_probes"] == ([] if preflight_status == "ok" else ["invalid_session"])
    assert payload["checked_at"]


def test_get_auth_readiness_redacts_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _preflight(scan_config: object) -> PreflightResult:
        auth_context = getattr(scan_config, "auth_context")
        assert auth_context.bearer_token == "very-secret-token"
        return PreflightResult(
            status="failed",
            failures=["invalid_session"],
            missing_roles=[],
            missing_tenants=[],
            csrf_status="not_checked",
        )

    monkeypatch.setattr(scans_module, "preflight_auth_check", _preflight)

    response = _scans_client().get(
        "/scans/auth/readiness",
        params={
            "target_url": "https://app.example.com",
            "bearer_token": "very-secret-token",
            "session_cookie": "session-secret-cookie",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    serialized = json.dumps(payload)
    assert payload["redacted_evidence"]["bearer_token"] == "very***"
    assert payload["redacted_evidence"]["session_cookie"] == "sess***"
    assert "very-secret-token" not in serialized
    assert "session-secret-cookie" not in serialized


def test_get_auth_readiness_accepts_session_cookie_header(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _preflight(scan_config: object) -> PreflightResult:
        auth_context = getattr(scan_config, "auth_context")
        assert auth_context.cookies == [
            {"name": "sid", "value": "abc123"},
            {"name": "csrftoken", "value": "csrf123"},
        ]
        return PreflightResult(
            status="ok",
            failures=[],
            missing_roles=[],
            missing_tenants=[],
            csrf_status="ok",
        )

    monkeypatch.setattr(scans_module, "preflight_auth_check", _preflight)

    response = _scans_client().get(
        "/scans/auth/readiness",
        params={
            "target_url": "https://app.example.com",
            "session_cookie": "sid=abc123; csrftoken=csrf123",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["readiness_score"] == 1.0
    assert payload["redacted_evidence"]["session_cookie"] == "sid=***"


@pytest.mark.asyncio
async def test_get_scan_preflight_returns_structured_readiness_report(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = uuid4()
    target_id = uuid4()
    scan = Scan(id=scan_id, target_id=target_id, status=ScanStatus.running, phase="recon")
    target = Target(
        id=target_id,
        url="https://app.example.com/dashboard",
        name="app",
        config={"unauth_mode": False, "seed_urls": ["https://app.example.com/dashboard"]},
    )
    auth_context = AuthContext(
        scan_id=scan_id,
        type="session",
        session_snapshot={"cookies": [{"name": "sid", "value": "abc"}]},
        health={"status": "healthy"},
    )
    db = _PreflightDb(scan=scan, target=target, auth_context=auth_context)

    async def _session_probe(**kwargs: object) -> tuple[bool, str]:
        assert kwargs["requires_auth"] is True
        return True, "Session probe returned HTTP 200"

    async def _target_probe(target_url: str) -> tuple[bool, str]:
        assert target_url == "https://app.example.com/dashboard"
        return True, "Target base URL responded with HTTP 200"

    monkeypatch.setattr(scans_module, "_probe_session_valid", _session_probe)
    monkeypatch.setattr(scans_module, "_probe_target_reachable", _target_probe)

    response = await scans_module.get_scan_preflight(scan_id, db)  # type: ignore[arg-type]

    assert response.overall_ready is True
    assert response.blocking_issues == []
    assert [check.check_name for check in response.checks] == [
        "session_valid",
        "target_reachable",
        "discovery_config_complete",
        "auth_config_present",
    ]
    assert all(check.passed for check in response.checks)


@pytest.mark.asyncio
async def test_create_scan_invalid_session_preflight_returns_422(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _failed_preflight(scan_config: object) -> PreflightResult:
        del scan_config
        return PreflightResult(
            status="failed",
            failures=["invalid_session"],
            missing_roles=[],
            missing_tenants=[],
            csrf_status="not_checked",
        )

    monkeypatch.setattr(scans_module, "preflight_auth_check", _failed_preflight)
    payload = ScanCreate(
        target_url="https://app.example.com",
        auth_context=AuthContextCreate(type="token", bearer_token="expired-token"),
    )

    with pytest.raises(HTTPException) as exc_info:
        await scans_module.create_scan(payload, db=None)  # type: ignore[arg-type]

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["status"] == "failed"
    assert exc_info.value.detail["failures"] == ["invalid_session"]


@pytest.mark.asyncio
async def test_create_scan_missing_role_preflight_returns_422(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _failed_preflight(scan_config: object) -> PreflightResult:
        del scan_config
        return PreflightResult(
            status="failed",
            failures=["missing_role"],
            missing_roles=["alice"],
            missing_tenants=[],
            csrf_status="ok",
        )

    monkeypatch.setattr(scans_module, "preflight_auth_check", _failed_preflight)
    payload = ScanCreate(
        target_url="https://app.example.com",
        identities=[
            {
                "name": "alice",
                "auth_context": {"type": "token", "bearer_token": "valid-token"},
                "tenant_hint": "tenant-a",
            }
        ],
    )

    with pytest.raises(HTTPException) as exc_info:
        await scans_module.create_scan(payload, db=None)  # type: ignore[arg-type]

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["failures"] == ["missing_role"]
    assert exc_info.value.detail["missing_roles"] == ["alice"]
