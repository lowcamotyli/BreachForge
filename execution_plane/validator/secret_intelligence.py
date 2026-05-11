from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SecretType(Enum):
    JWT = "JWT"
    BEARER = "BEARER"
    API_KEY = "API_KEY"
    SESSION_TOKEN = "SESSION_TOKEN"
    GENERIC_SECRET = "GENERIC_SECRET"


@dataclass(slots=True)
class JWTMeta:
    iss: str | None = None
    aud: str | None = None
    sub: str | None = None
    client_id: str | None = None
    exp: int | None = None
    iat: int | None = None
    nbf: int | None = None
    scope: str | None = None
    scp: str | None = None
    role: Any = None
    roles: Any = None
    claims: dict[str, Any] = field(default_factory=dict)
    ttl_seconds: int | None = None
    expired: bool = False
    long_lived: bool = False
    missing_exp: bool = False


@dataclass(slots=True)
class SecretMetadata:
    secret_type: SecretType
    fingerprint: str
    length_bucket: str
    entropy_bucket: str
    jwt_meta: JWTMeta | None = field(default=None)


class PrivilegeLevel(Enum):
    anonymous = "anonymous"
    user = "user"
    elevated_user = "elevated_user"
    admin = "admin"
    service = "service"
    unknown = "unknown"


@dataclass(slots=True)
class PrivilegeHint:
    source: str
    level: PrivilegeLevel
    confidence: float
    notes: str


@dataclass(slots=True)
class PrivilegeFingerprint:
    observed_access_level: PrivilegeLevel
    inferred_level: PrivilegeLevel
    confidence: float
    hints: list[PrivilegeHint]
    evidence_endpoints: list[str]


@dataclass(slots=True)
class SecretLifecycleAssessment:
    ttl_seconds: int | None = None
    ttl_bucket: str = "unknown"
    expired: bool = False
    long_lived: bool = False
    missing_exp: bool = False
    active_during_scan: bool = False


def bucket_ttl(ttl_seconds: int | None, expired: bool) -> str:
    if expired:
        return "expired"
    if ttl_seconds is None:
        return "unknown"
    if ttl_seconds < 3600:
        return "short"
    if ttl_seconds < 86400:
        return "medium"
    return "long"


def assess_lifecycle(meta: SecretMetadata, active_during_scan: bool = False) -> SecretLifecycleAssessment:
    if meta.jwt_meta is not None:
        ttl_seconds: int | None = meta.jwt_meta.ttl_seconds
        expired: bool = meta.jwt_meta.expired
        long_lived: bool = meta.jwt_meta.long_lived
        missing_exp: bool = meta.jwt_meta.missing_exp
    else:
        ttl_seconds = None
        expired = False
        long_lived = False
        missing_exp = False

    ttl_bucket: str = bucket_ttl(ttl_seconds, expired)
    return SecretLifecycleAssessment(
        ttl_seconds=ttl_seconds,
        ttl_bucket=ttl_bucket,
        expired=expired,
        long_lived=long_lived,
        missing_exp=missing_exp,
        active_during_scan=active_during_scan,
    )


_JWT_PATTERN: re.Pattern[str] = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_SESSION_PATTERN: re.Pattern[str] = re.compile(r"(?i)(sess|sid|session)")
_API_KEY_PATTERN: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_\-\.=]{20,}$")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0

    counts: dict[str, int] = {}
    for char in s:
        counts[char] = counts.get(char, 0) + 1

    entropy: float = 0.0
    total: int = len(s)
    for count in counts.values():
        probability: float = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def _decode_jwt_meta(token: str, now: datetime | None = None) -> JWTMeta:
    try:
        parts: list[str] = token.split(".")

        def _decode_segment(segment: str) -> dict[str, Any]:
            padded: str = segment + "=" * ((4 - len(segment) % 4) % 4)
            decoded_bytes: bytes = base64.urlsafe_b64decode(padded.encode("utf-8"))
            parsed: Any = json.loads(decoded_bytes.decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed
            raise ValueError("JWT segment is not a JSON object")

        _header: dict[str, Any] = _decode_segment(parts[0])
        payload: dict[str, Any] = _decode_segment(parts[1])

        exp_raw: Any = payload.get("exp")
        exp: int | None = exp_raw if isinstance(exp_raw, int) else None
        current_time: datetime = now or datetime.now(timezone.utc)
        ttl_seconds: int | None = exp - int(current_time.timestamp()) if exp is not None else None
        expired: bool = ttl_seconds < 0 if ttl_seconds is not None else False
        long_lived: bool = ttl_seconds > 86400 if ttl_seconds is not None and not expired else False

        return JWTMeta(
            iss=payload.get("iss") if isinstance(payload.get("iss"), str) else None,
            aud=payload.get("aud") if isinstance(payload.get("aud"), str) else None,
            sub=payload.get("sub") if isinstance(payload.get("sub"), str) else None,
            client_id=payload.get("client_id") if isinstance(payload.get("client_id"), str) else None,
            exp=exp,
            iat=payload.get("iat") if isinstance(payload.get("iat"), int) else None,
            nbf=payload.get("nbf") if isinstance(payload.get("nbf"), int) else None,
            scope=payload.get("scope") if isinstance(payload.get("scope"), str) else None,
            scp=payload.get("scp") if isinstance(payload.get("scp"), str) else None,
            role=payload.get("role"),
            roles=payload.get("roles"),
            claims=payload,
            ttl_seconds=ttl_seconds,
            expired=expired,
            long_lived=long_lived,
            missing_exp=exp is None,
        )
    except Exception:
        return JWTMeta(missing_exp=True)


def classify(raw_secret: str, now: datetime | None = None) -> SecretMetadata:
    if _JWT_PATTERN.match(raw_secret):
        secret_type: SecretType = SecretType.JWT
    elif raw_secret.lower().startswith("bearer "):
        secret_type = SecretType.BEARER
    elif _SESSION_PATTERN.search(raw_secret):
        secret_type = SecretType.SESSION_TOKEN
    elif _API_KEY_PATTERN.match(raw_secret):
        secret_type = SecretType.API_KEY
    else:
        secret_type = SecretType.GENERIC_SECRET

    fingerprint: str = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()[:16]
    length_bucket: str = "short" if len(raw_secret) < 32 else "medium" if len(raw_secret) <= 128 else "long"
    entropy: float = _shannon_entropy(raw_secret)
    entropy_bucket: str = "low" if entropy < 2.5 else "medium" if entropy <= 4.0 else "high"
    jwt_meta: JWTMeta | None = _decode_jwt_meta(raw_secret, now) if secret_type is SecretType.JWT else None

    return SecretMetadata(
        secret_type=secret_type,
        fingerprint=fingerprint,
        length_bucket=length_bucket,
        entropy_bucket=entropy_bucket,
        jwt_meta=jwt_meta,
    )


def infer_privilege_from_status(status_code: int, endpoint: str) -> PrivilegeHint | None:
    _ = endpoint
    if status_code == 200:
        return PrivilegeHint(
            source="status_code",
            level=PrivilegeLevel.user,
            confidence=0.6,
            notes="endpoint returned 200",
        )
    if status_code == 401:
        return PrivilegeHint(
            source="status_code",
            level=PrivilegeLevel.anonymous,
            confidence=0.9,
            notes="auth required",
        )
    if status_code == 403:
        return PrivilegeHint(
            source="status_code",
            level=PrivilegeLevel.user,
            confidence=0.5,
            notes="authenticated but forbidden",
        )
    if status_code == 404:
        return None
    return None


def infer_privilege_from_endpoint(endpoint: str) -> PrivilegeHint | None:
    endpoint_lc: str = endpoint.lower()
    if "/admin" in endpoint_lc:
        return PrivilegeHint(
            source="endpoint_path",
            level=PrivilegeLevel.admin,
            confidence=0.5,
            notes="admin endpoint hint",
        )
    if "/billing" in endpoint_lc:
        return PrivilegeHint(
            source="endpoint_path",
            level=PrivilegeLevel.elevated_user,
            confidence=0.4,
            notes="billing endpoint hint",
        )
    if "/settings" in endpoint_lc:
        return PrivilegeHint(
            source="endpoint_path",
            level=PrivilegeLevel.elevated_user,
            confidence=0.4,
            notes="settings endpoint hint",
        )
    if "/users" in endpoint_lc:
        return PrivilegeHint(
            source="endpoint_path",
            level=PrivilegeLevel.user,
            confidence=0.3,
            notes="users endpoint hint",
        )
    return None


def _normalize_claim_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [part.strip().lower() for part in re.split(r"[\s,]+", value) if part.strip()]
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            if isinstance(item, str):
                values.extend([part.strip().lower() for part in re.split(r"[\s,]+", item) if part.strip()])
        return values
    return []


def _jwt_claims_to_hints(jwt_meta: JWTMeta) -> list[PrivilegeHint]:
    hints: list[PrivilegeHint] = []
    claims_raw: Any = getattr(jwt_meta, "claims", {})
    claims: dict[str, Any] = claims_raw if isinstance(claims_raw, dict) else {}

    scope_values: list[str] = []
    for key in ("scope", "scp"):
        scope_values.extend(_normalize_claim_values(claims.get(key)))

    role_values: list[str] = []
    for key in ("role", "roles"):
        role_values.extend(_normalize_claim_values(claims.get(key)))

    has_scope_admin: bool = "admin" in scope_values
    if has_scope_admin:
        hints.append(
            PrivilegeHint(
                source="jwt_claim",
                level=PrivilegeLevel.admin,
                confidence=0.3,
                notes="JWT scope claim (untrusted hint)",
            )
        )

    has_scope_elevated: bool = ("write" in scope_values) or ("read:admin" in scope_values)
    if has_scope_elevated:
        hints.append(
            PrivilegeHint(
                source="jwt_claim",
                level=PrivilegeLevel.elevated_user,
                confidence=0.25,
                notes="JWT scope claim (untrusted hint)",
            )
        )

    has_role_admin: bool = ("admin" in role_values) or ("administrator" in role_values)
    if has_role_admin:
        hints.append(
            PrivilegeHint(
                source="jwt_claim",
                level=PrivilegeLevel.admin,
                confidence=0.3,
                notes="JWT role claim (untrusted hint)",
            )
        )

    has_role_user: bool = "user" in role_values
    if has_role_user:
        hints.append(
            PrivilegeHint(
                source="jwt_claim",
                level=PrivilegeLevel.user,
                confidence=0.2,
                notes="JWT role claim (untrusted hint)",
            )
        )

    return hints


def _level_rank(level: PrivilegeLevel) -> int:
    ordering: dict[PrivilegeLevel, int] = {
        PrivilegeLevel.unknown: 0,
        PrivilegeLevel.anonymous: 1,
        PrivilegeLevel.user: 2,
        PrivilegeLevel.elevated_user: 3,
        PrivilegeLevel.admin: 4,
        PrivilegeLevel.service: 5,
    }
    return ordering[level]


def _max_level(levels: list[PrivilegeLevel]) -> PrivilegeLevel:
    if not levels:
        return PrivilegeLevel.unknown
    best: PrivilegeLevel = levels[0]
    for level in levels[1:]:
        if _level_rank(level) > _level_rank(best):
            best = level
    return best


def fingerprint_privilege(
    probe_results: list[tuple[str, int]],
    jwt_meta: JWTMeta | None = None,
) -> PrivilegeFingerprint:
    hints: list[PrivilegeHint] = []
    status_hints: list[PrivilegeHint] = []

    for endpoint, status_code in probe_results:
        status_hint: PrivilegeHint | None = infer_privilege_from_status(status_code, endpoint)
        if status_hint is not None:
            hints.append(status_hint)
            status_hints.append(status_hint)

        endpoint_hint: PrivilegeHint | None = infer_privilege_from_endpoint(endpoint)
        if endpoint_hint is not None:
            hints.append(endpoint_hint)

    jwt_hints: list[PrivilegeHint] = _jwt_claims_to_hints(jwt_meta) if jwt_meta is not None else []
    hints.extend(jwt_hints)

    observed_access_level: PrivilegeLevel = _max_level([hint.level for hint in status_hints])
    inferred_level: PrivilegeLevel = _max_level([hint.level for hint in jwt_hints])

    confidence_candidates: list[float] = [
        hint.confidence
        for hint in status_hints
        if _level_rank(hint.level) >= _level_rank(PrivilegeLevel.user)
    ]
    if confidence_candidates:
        confidence_raw: float = sum(confidence_candidates) / len(confidence_candidates)
        confidence: float = max(0.0, min(1.0, confidence_raw))
    else:
        confidence = 0.0

    evidence_endpoints: list[str] = [endpoint for endpoint, status_code in probe_results if status_code == 200]

    return PrivilegeFingerprint(
        observed_access_level=observed_access_level,
        inferred_level=inferred_level,
        confidence=confidence,
        hints=hints,
        evidence_endpoints=evidence_endpoints,
    )
