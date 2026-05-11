from __future__ import annotations

import json

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_STATE_CHANGING_METHODS: set[str] = {"POST", "PUT", "PATCH", "DELETE"}
_LOGIN_HINTS: tuple[str, ...] = ("login", "signin", "auth", "session", "token")
_NOISE_PATHS: tuple[str, ...] = ("/health", "/status", "/metrics", "/live", "/ready", "/ping")


class CsrfRule(AttackRule):
    requires_auth = True
    attack_class = "csrf"
    name = "CsrfRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        method = str(endpoint.method).upper()
        if method not in _STATE_CHANGING_METHODS:
            return False
        return True

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        hypothesis = {
            "probe_type": "csrf_no_token",
            "method": str(endpoint.method),
            "endpoint_path": str(endpoint.url_pattern),
            "stripped_headers": ["Origin", "Referer"],
        }
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="request",
                hypothesis=json.dumps(hypothesis, sort_keys=True),
                priority_score=0.7,
            )
        ]

    def expected_proof_signal(self) -> str:
        return "state-changing request accepted without CSRF token and without Origin/Referer"


class CookieAuditRule(AttackRule):
    requires_auth = True
    attack_class = "cookie_analysis"
    name = "CookieAuditRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        path_lower = endpoint.url_pattern.lower()
        if any(noise in path_lower for noise in _NOISE_PATHS):
            return False
        method = str(endpoint.method).upper()
        if method in _STATE_CHANGING_METHODS:
            return True
        return any(hint in path_lower for hint in _LOGIN_HINTS)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        path = str(endpoint.url_pattern)
        path_lower = path.lower()
        is_login_endpoint = any(hint in path_lower for hint in _LOGIN_HINTS)
        hypothesis = {
            "probe_type": "cookie_audit",
            "observe_set_cookie": True,
            "is_login_endpoint": is_login_endpoint,
        }
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="response.headers.set-cookie",
                hypothesis=json.dumps(hypothesis, sort_keys=True),
                priority_score=0.6,
            )
        ]

    def expected_proof_signal(self) -> str:
        return "Set-Cookie headers present with missing security flags"
