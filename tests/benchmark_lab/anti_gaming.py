from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import random
import uuid
from typing import Any


@dataclass
class AntiGamingConfig:
    seed: int
    randomize_ids: bool = True
    randomize_routes: bool = True
    randomize_tenant_names: bool = True

    def to_seed_string(self) -> str:
        return (
            f"seed={self.seed}|"
            f"randomize_ids={self.randomize_ids}|"
            f"randomize_routes={self.randomize_routes}|"
            f"randomize_tenant_names={self.randomize_tenant_names}"
        )


class AntiGamingTransformer:
    def __init__(self, config: AntiGamingConfig):
        self.config = config
        self._id_map: dict[str, str] = {}

    def _seeded_rng(self, namespace: str, value: str) -> random.Random:
        material = f"{self.config.seed}:{namespace}:{value}".encode("utf-8")
        digest = hashlib.sha256(material).digest()
        return random.Random(int.from_bytes(digest[:8], "big"))

    def _mapped_vuln_id(self, original_id: str) -> str:
        if original_id not in self._id_map:
            rng = self._seeded_rng("vuln_id", original_id)
            raw = rng.getrandbits(128)
            self._id_map[original_id] = str(uuid.UUID(int=raw))
        return self._id_map[original_id]

    def _suffix_for_route(self, route: str) -> str:
        rng = self._seeded_rng("route", route)
        return f"{rng.getrandbits(16):04x}"

    def _name_for_tenant(self, original: str) -> str:
        rng = self._seeded_rng("tenant", original)
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        token = "".join(rng.choice(alphabet) for _ in range(8))
        return f"org-{token}"

    @staticmethod
    def _apply_route_suffix(path: str, suffix: str) -> str:
        if path.endswith("/"):
            return f"{path[:-1]}-{suffix}/"
        return f"{path}-{suffix}"

    def transform_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        transformed = copy.deepcopy(manifest)

        if self.config.randomize_ids:
            for vuln in transformed.get("vulnerabilities", []):
                original_id = vuln.get("id")
                if isinstance(original_id, str):
                    vuln["id"] = self._mapped_vuln_id(original_id)

        route_map: dict[str, str] = {}
        if self.config.randomize_routes:
            all_routes: set[str] = set()
            for key in ("expected_surface", "expected_endpoints", "discovery_surface"):
                values = transformed.get(key, [])
                if isinstance(values, list):
                    all_routes.update(v for v in values if isinstance(v, str))

            for vuln in transformed.get("vulnerabilities", []):
                endpoint = vuln.get("endpoint")
                if isinstance(endpoint, str):
                    all_routes.add(endpoint)

            route_map = {
                route: self._apply_route_suffix(route, self._suffix_for_route(route))
                for route in all_routes
            }

            for key in ("expected_surface", "expected_endpoints", "discovery_surface"):
                values = transformed.get(key)
                if isinstance(values, list):
                    transformed[key] = [route_map.get(v, v) for v in values]

            for vuln in transformed.get("vulnerabilities", []):
                endpoint = vuln.get("endpoint")
                if isinstance(endpoint, str):
                    vuln["endpoint"] = route_map.get(endpoint, endpoint)

        if self.config.randomize_tenant_names:
            tenant_map: dict[str, str] = {}
            for identity in transformed.get("identities", []):
                if not isinstance(identity, dict):
                    continue
                tenant = identity.get("tenant")
                if isinstance(tenant, str):
                    if tenant not in tenant_map:
                        tenant_map[tenant] = self._name_for_tenant(tenant)
                    identity["tenant"] = tenant_map[tenant]

        return transformed

    def transform_ground_truth(self, gt: dict[str, Any]) -> dict[str, Any]:
        transformed = copy.deepcopy(gt)
        if not self.config.randomize_ids:
            return transformed

        for vuln in transformed.get("vulnerabilities", []):
            original_id = vuln.get("id")
            if isinstance(original_id, str):
                vuln["id"] = self._mapped_vuln_id(original_id)
        return transformed
