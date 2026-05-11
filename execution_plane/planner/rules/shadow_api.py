from __future__ import annotations

import json
import re
from typing import ClassVar
from uuid import UUID

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_ADMIN_PATHS: list[str] = ["/admin/", "/internal/", "/management/", "/actuator/", "/debug/", "/console/", "/ops/"]
_DOC_PATHS: list[str] = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html", "/api/swagger"]
_BACKUP_EXTENSIONS: list[str] = [".bak", ".old", ".swp", ".tmp", "~", ".php.bak"]
_VERSION_VARIANTS: list[str] = ["/api/v0", "/api/v1", "/api/v2", "/api/beta", "/v0", "/v1"]
_ADMIN_TASK_COUNTER: dict[str, int] = {}  # scan_id -> count of admin tasks emitted


class DeprecatedVersionRule(AttackRule):
    attack_class = "api_inventory"
    name = "DeprecatedVersionRule"
    requires_auth: ClassVar[bool] = False

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        return bool(re.search(r"/api/|/v\d+/", endpoint.url_pattern))

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        existing_patterns = {e.url_pattern for e in context.asset_map.endpoints}
        base = endpoint.url_pattern
        # Strip existing version prefix to get base path for permutation
        base_stripped = re.sub(r"(/api)?/v\d+/", "/", base)
        base_stripped = re.sub(r"^/v\d+/", "/", base_stripped)
        tasks: list[AttackTask] = []
        for variant_prefix in _VERSION_VARIANTS:
            candidate = variant_prefix + base_stripped.rstrip("/")
            if candidate in existing_patterns:
                continue
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter="url",
                    hypothesis=json.dumps(
                        {"probe_type": "deprecated_version", "target_url": candidate, "requires_auth": False, "method": "GET"}
                    ),
                    priority_score=0.70,
                )
            )
            if len(tasks) >= 6:
                break
        return tasks

    def expected_proof_signal(self) -> str:
        return "deprecated_endpoint_active"


class AdminEndpointRule(AttackRule):
    attack_class = "api_inventory"
    name = "AdminEndpointRule"
    requires_auth: ClassVar[bool] = False
    MAX_WORDLIST_SIZE: ClassVar[int] = 100
    _MAX_ADMIN_TASKS: ClassVar[int] = 20

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        if endpoint.method.upper() != "GET":
            return False
        # Only apply when asset map has API-like surface worth fuzzing
        return any(
            re.search(r"/api/|/v\d+/|/graphql", e.url_pattern)
            for e in asset_map.endpoints
        )

    def build_wordlist(self, asset_map: dict) -> list[str]:
        app_specific: list[str] = []
        seen: set[str] = set()

        def _normalize_path(raw_path: object) -> str | None:
            if not isinstance(raw_path, str):
                return None
            candidate = raw_path.strip()
            if not candidate:
                return None
            if "://" in candidate:
                from urllib.parse import urlparse

                candidate = urlparse(candidate).path
            candidate = candidate.split("?", 1)[0].split("#", 1)[0].strip()
            if not candidate:
                return None
            if not candidate.startswith("/"):
                candidate = f"/{candidate}"
            normalized = "/" + "/".join(seg for seg in candidate.split("/") if seg)
            return normalized or None

        def _push(path: str) -> None:
            if path not in seen:
                seen.add(path)
                app_specific.append(path)

        def _extract_paths(values: object) -> None:
            if isinstance(values, str):
                normalized = _normalize_path(values)
                if normalized is not None:
                    _push(normalized)
                return
            if isinstance(values, list):
                for item in values:
                    _extract_paths(item)
                return
            if isinstance(values, dict):
                for key in ("path", "url", "endpoint", "url_pattern"):
                    if key in values:
                        normalized = _normalize_path(values.get(key))
                        if normalized is not None:
                            _push(normalized)
                return

        _extract_paths(asset_map.get("paths", []))
        _extract_paths(asset_map.get("js_endpoints", []))
        _extract_paths(asset_map.get("robots_paths", []))

        endpoints = asset_map.get("endpoints", [])
        if isinstance(endpoints, list):
            for endpoint in endpoints:
                if isinstance(endpoint, dict):
                    _extract_paths(endpoint.get("url_pattern"))
                    _extract_paths(endpoint.get("path"))
                else:
                    url_pattern = getattr(endpoint, "url_pattern", None)
                    if isinstance(url_pattern, str):
                        _extract_paths(url_pattern)

        segment_candidates: list[str] = []
        for path in list(app_specific):
            segments = [seg for seg in path.strip("/").split("/") if seg]
            for segment in segments:
                lowered = segment.lower()
                segment_candidates.append(f"/{lowered}")
                if re.fullmatch(r"v\d+", lowered) or lowered == "api":
                    segment_candidates.append(f"/api/{lowered}" if lowered != "api" else "/api")
        for candidate in segment_candidates:
            _push(candidate)

        standard_paths = [
            "/api/v1",
            "/api/v2",
            "/actuator/health",
            "/actuator/info",
            "/debug",
            "/console",
            "/.well-known/security.txt",
            "/.well-known/openid-configuration",
            "/swagger-ui.html",
            "/api-docs",
            "/graphql",
            "/admin",
            "/internal",
        ]
        generic: list[str] = []
        for path in standard_paths:
            if path not in seen:
                generic.append(path)
                seen.add(path)

        combined = app_specific + generic
        return combined[: self.MAX_WORDLIST_SIZE]

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        scan_key = str(context.scan_id)
        current_count = _ADMIN_TASK_COUNTER.get(scan_key, 0)
        if current_count >= self._MAX_ADMIN_TASKS:
            return []
        from urllib.parse import urlparse

        base_url = endpoint.url_pattern.split("/")[0:3]
        origin = "/".join(base_url) if base_url else ""
        tasks: list[AttackTask] = []
        for path in _ADMIN_PATHS:
            if current_count + len(tasks) >= self._MAX_ADMIN_TASKS:
                break
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter="url",
                    hypothesis=json.dumps(
                        {"probe_type": "admin_endpoint_fuzz", "target_url": path, "requires_auth": False, "method": "GET"}
                    ),
                    priority_score=0.75,
                )
            )
        _ADMIN_TASK_COUNTER[scan_key] = current_count + len(tasks)
        return tasks

    def expected_proof_signal(self) -> str:
        return "admin_endpoint_accessible"


class ApiDocExposureRule(AttackRule):
    attack_class = "api_doc_exposure"
    name = "ApiDocExposureRule"
    requires_auth: ClassVar[bool] = False

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        if not any(re.search(r"/api/|/v\d+/|/graphql", e.url_pattern) for e in asset_map.endpoints):
            return False
        already = any("swagger" in e.url_pattern.lower() or "openapi" in e.url_pattern.lower() for e in asset_map.endpoints)
        return not already

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="url",
                hypothesis=json.dumps({"probe_type": "api_doc_exposure", "target_url": path, "requires_auth": False, "method": "GET"}),
                priority_score=0.80,
            )
            for path in _DOC_PATHS
        ]

    def expected_proof_signal(self) -> str:
        return "api_spec_exposed"


class BackupFileRule(AttackRule):
    attack_class = "backup_file_exposure"
    name = "BackupFileRule"
    requires_auth: ClassVar[bool] = False
    _MAX_BACKUP_TASKS: ClassVar[int] = 50

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        last_seg = endpoint.url_pattern.rstrip("/").rsplit("/", 1)[-1]
        return "." in last_seg

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        tasks: list[AttackTask] = []
        base = endpoint.url_pattern.rstrip("/")
        for ext in _BACKUP_EXTENSIONS:
            if len(tasks) >= self._MAX_BACKUP_TASKS:
                break
            candidate = base + ext
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter="url",
                    hypothesis=json.dumps(
                        {"probe_type": "backup_file_exposure", "target_url": candidate, "requires_auth": False, "method": "GET"}
                    ),
                    priority_score=0.65,
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "backup_file_accessible"
