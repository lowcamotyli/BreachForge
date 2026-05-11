from __future__ import annotations

from execution_plane.planner.rules.base import AttackRule, AssetMap, ScanContext
from storage.db.models import AttackTask, Endpoint


class HttpSmugglingRule(AttackRule):
    requires_auth = False
    attack_class = "http_smuggling"
    name = "HttpSmugglingRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return endpoint.method.strip().upper() in {"POST", "PUT"}

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        hypothesis = "Check for CL.TE smuggling via differential timeout or poisoned response prefix"
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter=None,
                hypothesis=hypothesis,
                priority_score=0.78,
            )
        ]

    def expected_proof_signal(self) -> str:
        return "Conflicting transfer semantics trigger differential proxy/backend behavior"


class HttpCacheAttackRule(AttackRule):
    requires_auth = False
    attack_class = "cache_attack"
    name = "HttpCacheAttackRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return endpoint.method.strip().upper() == "GET" and endpoint.observed_content_type is not None

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        hypothesis = "Probe cache-keying via host header injection and static extension path traversal"
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter=None,
                hypothesis=hypothesis,
                priority_score=0.74,
            )
        ]

    def expected_proof_signal(self) -> str:
        return "Cache behavior diverges across keyed and unkeyed request variants"
