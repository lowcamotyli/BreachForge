from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from execution_plane.validator.secret_intelligence import (
    JWTMeta,
    PrivilegeFingerprint,
    PrivilegeHint,
    PrivilegeLevel,
    SecretLifecycleAssessment,
    SecretType,
    _decode_jwt_meta,
    _jwt_claims_to_hints,
    _level_rank,
    assess_lifecycle,
    bucket_ttl,
    classify,
    fingerprint_privilege,
    infer_privilege_from_endpoint,
    infer_privilege_from_status,
)


def _encode_json_segment(payload: dict[str, object]) -> str:
    raw: str = json.dumps(payload, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("utf-8").rstrip("=")


def _make_jwt(payload: dict[str, object]) -> str:
    header: dict[str, object] = {"alg": "HS256"}
    return f"{_encode_json_segment(header)}.{_encode_json_segment(payload)}.sig"


def test_classify_jwt() -> None:
    fixture: str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig"
    assert classify(fixture).secret_type is SecretType.JWT


def test_classify_bearer() -> None:
    assert classify("bearer abc123def456").secret_type is SecretType.BEARER


def test_classify_api_key() -> None:
    assert classify("sk-abcdefghijklmnopqrst").secret_type is SecretType.API_KEY


def test_classify_session_token() -> None:
    assert classify("sess_abc123xyz").secret_type is SecretType.SESSION_TOKEN


def test_classify_generic() -> None:
    assert classify("short").secret_type is SecretType.GENERIC_SECRET


def test_fingerprint_deterministic() -> None:
    raw: str = "same-secret-value"
    assert classify(raw).fingerprint == classify(raw).fingerprint


def test_fingerprint_no_raw_value() -> None:
    raw: str = "do-not-store-this-secret"
    assert raw not in classify(raw).fingerprint


def test_jwt_claims_extraction() -> None:
    now: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc)
    payload: dict[str, object] = {
        "iss": "issuer-service",
        "sub": "user-123",
        "exp": int(now.timestamp()) + 600,
    }
    meta: JWTMeta | None = classify(_make_jwt(payload), now=now).jwt_meta
    assert meta is not None
    assert meta.iss == "issuer-service"
    assert meta.sub == "user-123"
    assert meta.exp == int(now.timestamp()) + 600


def test_jwt_ttl_expired() -> None:
    now: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc)
    token: str = _make_jwt({"exp": int(now.timestamp()) - 60})
    meta: JWTMeta | None = classify(token, now=now).jwt_meta
    assert meta is not None
    assert meta.expired is True
    assert meta.ttl_seconds is not None
    assert meta.ttl_seconds < 0


def test_jwt_ttl_long_lived() -> None:
    now: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc)
    token: str = _make_jwt({"exp": int(now.timestamp()) + 172800})
    meta: JWTMeta | None = classify(token, now=now).jwt_meta
    assert meta is not None
    assert meta.long_lived is True


def test_jwt_missing_exp() -> None:
    now: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc)
    token: str = _make_jwt({"iss": "issuer-only"})
    meta: JWTMeta | None = classify(token, now=now).jwt_meta
    assert meta is not None
    assert meta.missing_exp is True
    assert meta.ttl_seconds is None


def test_malformed_jwt_no_raise() -> None:
    meta: JWTMeta = _decode_jwt_meta("notajwt.at.all")
    assert isinstance(meta, JWTMeta)


def test_privilege_level_ordering() -> None:
    order = [
        PrivilegeLevel.unknown,
        PrivilegeLevel.anonymous,
        PrivilegeLevel.user,
        PrivilegeLevel.elevated_user,
        PrivilegeLevel.admin,
        PrivilegeLevel.service,
    ]
    ranks = [_level_rank(l) for l in order]
    assert ranks == sorted(ranks)


def test_infer_privilege_from_status_200() -> None:
    hint = infer_privilege_from_status(200, "/api/data")
    assert hint is not None
    assert hint.level == PrivilegeLevel.user
    assert hint.confidence == 0.6
    assert hint.source == "status_code"


def test_infer_privilege_from_status_401() -> None:
    hint = infer_privilege_from_status(401, "/api/data")
    assert hint is not None
    assert hint.level == PrivilegeLevel.anonymous
    assert hint.confidence == 0.9


def test_infer_privilege_from_status_403() -> None:
    hint = infer_privilege_from_status(403, "/api/data")
    assert hint is not None
    assert hint.level == PrivilegeLevel.user
    assert hint.confidence == 0.5


def test_infer_privilege_from_status_404() -> None:
    assert infer_privilege_from_status(404, "/api/data") is None


def test_infer_privilege_from_endpoint_admin() -> None:
    hint = infer_privilege_from_endpoint("/admin/dashboard")
    assert hint is not None
    assert hint.level == PrivilegeLevel.admin
    assert hint.confidence == 0.5
    assert hint.source == "endpoint_path"


def test_infer_privilege_from_endpoint_billing() -> None:
    hint = infer_privilege_from_endpoint("/billing/invoices")
    assert hint is not None
    assert hint.level == PrivilegeLevel.elevated_user


def test_infer_privilege_from_endpoint_unknown() -> None:
    assert infer_privilege_from_endpoint("/api/health") is None


def test_jwt_claims_admin_scope() -> None:
    jwt_meta = JWTMeta(
        sub="u1",
        scope="admin openid",
        claims={"scope": "admin openid"},
    )
    hints = _jwt_claims_to_hints(jwt_meta)
    admin_hints = [h for h in hints if h.level == PrivilegeLevel.admin]
    assert len(admin_hints) >= 1
    assert all(h.source == "jwt_claim" for h in admin_hints)
    assert all("untrusted hint" in h.notes for h in admin_hints)


def test_jwt_claims_role_list() -> None:
    jwt_meta = JWTMeta(
        sub="u1",
        roles=["admin", "user"],
        claims={"roles": ["admin", "user"]},
    )
    hints = _jwt_claims_to_hints(jwt_meta)
    admin_hints = [h for h in hints if h.level == PrivilegeLevel.admin]
    assert len(admin_hints) >= 1


def test_jwt_claims_empty() -> None:
    jwt_meta = JWTMeta(
        sub="u1",
        claims={},
    )
    assert _jwt_claims_to_hints(jwt_meta) == []


def test_fingerprint_privilege_observed_from_status() -> None:
    fp = fingerprint_privilege([("/api/data", 200)])
    assert fp.observed_access_level == PrivilegeLevel.user
    assert fp.confidence > 0


def test_fingerprint_privilege_inferred_from_jwt() -> None:
    jwt_meta = JWTMeta(
        sub="u1",
        claims={"scope": "admin"},
    )
    fp = fingerprint_privilege([("/api/data", 401)], jwt_meta=jwt_meta)
    assert fp.inferred_level == PrivilegeLevel.admin
    assert fp.observed_access_level == PrivilegeLevel.anonymous


def test_fingerprint_privilege_evidence_endpoints() -> None:
    fp = fingerprint_privilege(
        [("/api/ok", 200), ("/api/forbidden", 403), ("/api/unauth", 401)]
    )
    assert "/api/ok" in fp.evidence_endpoints
    assert "/api/forbidden" not in fp.evidence_endpoints
    assert "/api/unauth" not in fp.evidence_endpoints


def test_fingerprint_privilege_no_jwt_pollution_in_observed() -> None:
    jwt_meta = JWTMeta(
        sub="u1",
        claims={"roles": ["admin"]},
    )
    fp = fingerprint_privilege([("/api/data", 401)], jwt_meta=jwt_meta)
    assert fp.observed_access_level == PrivilegeLevel.anonymous


def test_bucket_ttl_expired() -> None:
    assert bucket_ttl(ttl_seconds=-3600, expired=True) == "expired"


def test_bucket_ttl_short() -> None:
    assert bucket_ttl(ttl_seconds=1800, expired=False) == "short"


def test_bucket_ttl_medium() -> None:
    assert bucket_ttl(ttl_seconds=7200, expired=False) == "medium"


def test_bucket_ttl_long() -> None:
    assert bucket_ttl(ttl_seconds=172800, expired=False) == "long"


def test_bucket_ttl_unknown() -> None:
    assert bucket_ttl(ttl_seconds=None, expired=False) == "unknown"


def test_assess_lifecycle_jwt_expired() -> None:
    now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    token = _make_jwt(
        {"sub": "u1", "iat": int(now.timestamp()) - 7200, "exp": int(now.timestamp()) - 3600}
    )
    meta = classify(token, now=now)
    la = assess_lifecycle(meta)
    assert la.expired is True
    assert la.ttl_bucket == "expired"


def test_assess_lifecycle_jwt_long_lived() -> None:
    now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    token = _make_jwt(
        {"sub": "u1", "iat": int(now.timestamp()), "exp": int(now.timestamp()) + 172800}
    )
    meta = classify(token, now=now)
    la = assess_lifecycle(meta)
    assert la.long_lived is True
    assert la.ttl_bucket == "long"


def test_assess_lifecycle_missing_exp() -> None:
    token = _make_jwt({"sub": "u1"})
    meta = classify(token)
    la = assess_lifecycle(meta)
    assert la.missing_exp is True
    assert la.ttl_bucket == "unknown"


def test_assess_lifecycle_api_key_no_jwt() -> None:
    meta = classify("sk-abcdefghijklmnopqrst")
    la = assess_lifecycle(meta)
    assert la.ttl_seconds is None
    assert la.ttl_bucket == "unknown"


def test_assess_lifecycle_active_during_scan_flag() -> None:
    token = _make_jwt({"sub": "u1"})
    meta = classify(token)
    la = assess_lifecycle(meta, active_during_scan=True)
    assert la.active_during_scan is True
