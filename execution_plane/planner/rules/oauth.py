from __future__ import annotations

import json
from typing import Any

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_OAUTH_PATH_MARKERS: tuple[str, ...] = (
    "/oauth",
    "/authorize",
    "/authorization",
    "/token",
    "/callback",
    "/consent",
    "/openid",
)
_OAUTH_PARAMETER_NAMES: set[str] = {
    "client_id",
    "client_secret",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "code",
    "code_verifier",
    "code_challenge",
    "grant_type",
    "id_token",
    "access_token",
    "refresh_token",
}
_REDIRECT_KEYS: set[str] = {"redirect_uri", "redirect", "return_to", "callback", "next"}


class OauthRule(AttackRule):
    requires_auth = True
    attack_class = "oauth_redirect"
    name = "OauthRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        if self._looks_like_oauth_endpoint(endpoint):
            return True
        return any(self._looks_like_oauth_text(item) for item in self._signal_strings(asset_map))

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        oauth_relevant = self._looks_like_oauth_endpoint(endpoint)
        if not oauth_relevant:
            endpoint_lower = endpoint.url_pattern.lower()
            oauth_relevant = any(marker in endpoint_lower for marker in _OAUTH_PATH_MARKERS)
        if not oauth_relevant:
            return []

        method = endpoint.method.upper()
        base_params = {
            "method": method,
            "path": endpoint.url_pattern,
            "auth_required": endpoint.auth_required,
        }

        tasks: list[AttackTask] = []
        redirect_params = self._redirect_parameters(endpoint)
        for redirect_param in redirect_params:
            hypothesis = {
                "probe_type": "oauth_redirect",
                "target_parameter": redirect_param,
                "requires_auth": False,
                "manipulation_patterns": [
                    "partial-host-match:example.com.evil.test",
                    "subdomain-confusion:evil.example.com",
                    "path-traversal:/callback/../admin",
                    "scheme-host-override:https://callback.scanner.local/collect",
                ],
                "controlled_callback": {
                    "kind": "scanner_sandbox",
                    "host": "callback.scanner.local",
                    "note": "Never use external attacker infrastructure",
                },
                "params": base_params,
            }
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class="oauth_redirect",
                    target_parameter=redirect_param,
                    hypothesis=json.dumps(hypothesis, sort_keys=True),
                    priority_score=0.9,
                )
            )

        if self._supports_authorization_flow(endpoint):
            state_hypothesis = {
                "probe_type": "oauth_state_csrf",
                "requires_auth": False,
                "state_required": True,
                "response_indicators": ["code=", "access_token=", "id_token="],
                "params": base_params,
            }
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class="oauth_state_csrf",
                    target_parameter="state",
                    hypothesis=json.dumps(state_hypothesis, sort_keys=True),
                    priority_score=0.84,
                )
            )

        if self._supports_token_lifecycle(endpoint):
            token_hypothesis = {
                "probe_type": "oauth_token_reuse",
                "requires_auth": True,
                "check_after_logout": True,
                "token_types": ["access_token", "refresh_token"],
                "params": base_params,
            }
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class="oauth_token_reuse",
                    target_parameter="authorization",
                    hypothesis=json.dumps(token_hypothesis, sort_keys=True),
                    priority_score=0.82,
                )
            )

        error_hypothesis = {
            "probe_type": "oauth_error_disclosure",
            "requires_auth": False,
            "look_for": ["allowed_redirect_uris", "client_id", "internal_path"],
            "params": base_params,
        }
        tasks.append(
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class="oauth_error_disclosure",
                target_parameter="response",
                hypothesis=json.dumps(error_hypothesis, sort_keys=True),
                priority_score=0.7,
            )
        )

        return tasks

    def expected_proof_signal(self) -> str:
        return "OAuth flow accepts manipulated redirect/state, reuses tokens post-logout, or leaks sensitive error metadata"

    def _looks_like_oauth_endpoint(self, endpoint: Endpoint) -> bool:
        path = endpoint.url_pattern.lower()
        if any(marker in path for marker in _OAUTH_PATH_MARKERS):
            return True

        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            raw_name = parameter.get("name")
            if isinstance(raw_name, str) and raw_name.strip().lower() in _OAUTH_PARAMETER_NAMES:
                return True
        return False

    def _redirect_parameters(self, endpoint: Endpoint) -> list[str]:
        names: list[str] = []
        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            raw_name = parameter.get("name")
            if not isinstance(raw_name, str):
                continue
            normalized = raw_name.strip()
            if not normalized:
                continue
            if normalized.lower() in _REDIRECT_KEYS and normalized not in names:
                names.append(normalized)

        if any(part in endpoint.url_pattern.lower() for part in ("/authorize", "/callback", "/oauth")) and "redirect_uri" not in {
            item.lower() for item in names
        }:
            names.append("redirect_uri")
        return names

    def _supports_authorization_flow(self, endpoint: Endpoint) -> bool:
        path = endpoint.url_pattern.lower()
        if any(marker in path for marker in ("/authorize", "/authorization", "/consent", "/oauth")):
            return True
        param_names = {self._parameter_name(parameter) for parameter in endpoint.parameters}
        return "response_type" in param_names or "state" in param_names

    def _supports_token_lifecycle(self, endpoint: Endpoint) -> bool:
        path = endpoint.url_pattern.lower()
        if any(marker in path for marker in ("/token", "/revoke", "/logout", "/introspect")):
            return True
        param_names = {self._parameter_name(parameter) for parameter in endpoint.parameters}
        token_markers = {"access_token", "refresh_token", "authorization", "token"}
        return bool(param_names & token_markers)

    def _parameter_name(self, parameter: Any) -> str:
        if not isinstance(parameter, dict):
            return ""
        raw_name = parameter.get("name")
        if not isinstance(raw_name, str):
            return ""
        return raw_name.strip().lower()

    def _signal_strings(self, asset_map: AssetMap) -> list[str]:
        raw_signals = getattr(asset_map, "signals", None)
        if raw_signals is None:
            raw_signals = getattr(asset_map, "planning_signals", None)
        if not isinstance(raw_signals, dict):
            return []

        values: list[str] = []
        for value in raw_signals.values():
            if isinstance(value, str):
                values.append(value)
            elif isinstance(value, list):
                values.extend(item for item in value if isinstance(item, str))
        return values

    def _looks_like_oauth_text(self, value: str) -> bool:
        lowered = value.lower()
        if any(marker in lowered for marker in _OAUTH_PATH_MARKERS):
            return True
        return any(name in lowered for name in _OAUTH_PARAMETER_NAMES)
