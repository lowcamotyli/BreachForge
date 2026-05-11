from __future__ import annotations

import json
import re
from collections.abc import Iterable

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_DEFAULT_RESTRICTED_PATH_MARKERS: tuple[str, ...] = (
    "/admin/",
    "/internal/",
    "/management/",
    "/superuser/",
    "/ops/",
    "/system/",
)
_DEFAULT_RESTRICTED_VERBS: tuple[str, ...] = ("DELETE", "PUT", "PATCH")
_DEFAULT_LOW_PRIV_ROLES: tuple[str, ...] = ("user", "viewer", "guest")
_DEFAULT_ELEVATED_ROLES: tuple[str, ...] = ("admin", "manager")
_RESOURCE_PATH_HINT_RE = re.compile(r"\{[^}]+\}|\b(?:id|uuid|slug)\b|/\d+(?=/|$)", re.IGNORECASE)


class BflaRule(AttackRule):
    requires_auth = True
    attack_class = "bfla"
    name = "BflaRule"

    def __init__(
        self,
        restricted_path_markers: Iterable[str] = _DEFAULT_RESTRICTED_PATH_MARKERS,
        restricted_verbs: Iterable[str] = _DEFAULT_RESTRICTED_VERBS,
        low_priv_roles: Iterable[str] = _DEFAULT_LOW_PRIV_ROLES,
        elevated_roles: Iterable[str] = _DEFAULT_ELEVATED_ROLES,
    ) -> None:
        self._restricted_path_markers = tuple(marker.strip().lower() for marker in restricted_path_markers if marker.strip())
        self._restricted_verbs = {verb.strip().upper() for verb in restricted_verbs if verb.strip()}
        self._low_priv_roles = tuple(role.strip().lower() for role in low_priv_roles if role.strip())
        self._elevated_roles = tuple(role.strip().lower() for role in elevated_roles if role.strip())

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return self._is_restricted_path(endpoint.url_pattern) or (
            self._is_restricted_verb(endpoint.method) and self._is_resource_endpoint(endpoint.url_pattern)
        )

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        indicators: list[str] = []
        candidates: list[dict[str, object]] = []

        if self._is_restricted_path(endpoint.url_pattern):
            indicators.append("restricted_path")
            candidates.append(
                {
                    "probe_type": "bfla_admin_path_access",
                    "url_pattern": endpoint.url_pattern,
                    "method": endpoint.method.upper(),
                    "expected_low_priv_status": [403, 404],
                    "requires_cross_role_probing": True,
                    "required_identities": {
                        "low_privilege": list(self._low_priv_roles),
                        "elevated": list(self._elevated_roles),
                        "minimum_identities": 2,
                    },
                }
            )

        if self._is_restricted_verb(endpoint.method):
            indicators.append("restricted_http_verb")
            candidates.append(
                {
                    "probe_type": "bfla_verb_authorization",
                    "url_pattern": endpoint.url_pattern,
                    "method": endpoint.method.upper(),
                    "expected_low_priv_status": [403, 404, 405],
                    "restricted_verbs": sorted(self._restricted_verbs),
                    "resource_endpoint": self._is_resource_endpoint(endpoint.url_pattern),
                    "requires_cross_role_probing": True,
                    "required_identities": {
                        "low_privilege": list(self._low_priv_roles),
                        "elevated": list(self._elevated_roles),
                        "minimum_identities": 2,
                    },
                    "requires_safe_fixture_or_allow_mutation": True,
                    "mutation_allowed": False,
                }
            )

        if not candidates:
            return []

        hypothesis = {
            "attack_type": self.attack_class,
            "indicators": indicators,
            "candidates": candidates,
            "required_identities": {
                "low_privilege": list(self._low_priv_roles),
                "elevated": list(self._elevated_roles),
                "minimum_identities": 2,
            },
        }
        if "restricted_http_verb" in indicators:
            hypothesis["requires_safe_fixture_or_allow_mutation"] = True
            hypothesis["mutation_allowed"] = False

        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="authorization",
                hypothesis=json.dumps(hypothesis, sort_keys=True),
                priority_score=0.96 if "restricted_path" in indicators else 0.91,
            )
        ]

    def expected_proof_signal(self) -> str:
        return "Low-privilege identity successfully accesses admin-only function or restricted HTTP action"

    def _is_restricted_path(self, path: str) -> bool:
        normalized = self._normalize_path(path)
        if not normalized:
            return False
        return any(marker in normalized for marker in self._restricted_path_markers)

    def _is_restricted_verb(self, method: str) -> bool:
        return method.strip().upper() in self._restricted_verbs

    def _normalize_path(self, path: str) -> str:
        normalized = (path or "").strip().lower()
        if not normalized:
            return ""
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if not normalized.endswith("/"):
            normalized = f"{normalized}/"
        return normalized

    def _is_resource_endpoint(self, path: str) -> bool:
        normalized = self._normalize_path(path)
        if not normalized:
            return False
        if _RESOURCE_PATH_HINT_RE.search(normalized):
            return True
        segments = [segment for segment in normalized.strip("/").split("/") if segment]
        return len(segments) >= 2
