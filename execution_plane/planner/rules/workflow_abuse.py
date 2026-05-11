from __future__ import annotations

import json

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint

_START_HINTS: tuple[str, ...] = (
    "create",
    "start",
    "begin",
    "init",
    "draft",
    "cart",
    "login",
    "otp",
    "verify",
)

_FINALIZE_HINTS: tuple[str, ...] = (
    "approve",
    "confirm",
    "complete",
    "checkout",
    "submit",
    "pay",
    "ship",
    "activate",
)


class WorkflowAbuse(AttackRule):
    requires_auth = False
    attack_class = "workflow_abuse"
    name = "WorkflowAbuse"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        return bool(self._candidate_prerequisite_steps(endpoint, asset_map))

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        prerequisites = self._candidate_prerequisite_steps(endpoint, context.asset_map)
        tasks: list[AttackTask] = []
        auth_step_url = self._resolve_auth_step_url(endpoint=endpoint, asset_map=context.asset_map)
        chain_step_two_method = self._resolve_state_change_method(endpoint.method)
        chain_step_three_url = self._resolve_exploit_url(endpoint.url_pattern)
        for prereq in prerequisites:
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter="workflow_chain",
                    hypothesis=(
                        "Attempt terminal workflow action while skipping prerequisite step: "
                        f"required={prereq.method.upper()} {prereq.url_pattern}; "
                        f"attempted={endpoint.method.upper()} {endpoint.url_pattern}; "
                        "expect state-machine bypass if success is returned"
                    ),
                )
            )
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter="workflow_chain",
                    hypothesis=json.dumps(
                        {
                            "probe_type": "chain_model",
                            "prerequisite": "authenticated_session",
                            "state_chain": True,
                            "required_step": {
                                "method": prereq.method.upper(),
                                "url": prereq.url_pattern,
                            },
                            "chain_steps": [
                                {
                                    "step": 1,
                                    "action": "login/authenticate",
                                    "method": "POST",
                                    "url": auth_step_url,
                                },
                                {
                                    "step": 2,
                                    "action": "trigger_state_change",
                                    "method": chain_step_two_method,
                                    "url": endpoint.url_pattern,
                                    "extract": {"resource_id": "$.id"},
                                },
                                {
                                    "step": 3,
                                    "action": "exploit_state_change",
                                    "method": "GET",
                                    "url": chain_step_three_url,
                                },
                            ],
                        },
                        sort_keys=True,
                    ),
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "Request chain shows skipped prerequisite followed by successful terminal action"

    def _candidate_prerequisite_steps(self, endpoint: Endpoint, asset_map: AssetMap) -> list[Endpoint]:
        if not self._is_terminal_step(endpoint):
            return []

        endpoint_resource = self._resource_key(endpoint.url_pattern)
        prerequisites: list[Endpoint] = []
        seen: set[str] = set()

        for candidate in asset_map.endpoints:
            if candidate.id == endpoint.id:
                continue
            if self._resource_key(candidate.url_pattern) != endpoint_resource:
                continue
            if not self._is_prerequisite_step(candidate):
                continue

            key = f"{candidate.method.upper()}:{candidate.url_pattern}"
            if key in seen:
                continue
            seen.add(key)
            prerequisites.append(candidate)

        return prerequisites

    def _is_terminal_step(self, endpoint: Endpoint) -> bool:
        method = endpoint.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return False

        path = endpoint.url_pattern.lower()
        return any(token in path for token in _FINALIZE_HINTS)

    def _is_prerequisite_step(self, endpoint: Endpoint) -> bool:
        method = endpoint.method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH"}:
            return False

        path = endpoint.url_pattern.lower()
        if any(token in path for token in _START_HINTS):
            return True

        return endpoint.example_response_code in {200, 201, 202}

    def _resource_key(self, url_pattern: str) -> str:
        parts = [segment for segment in url_pattern.strip("/").split("/") if segment and not segment.startswith("{")]
        if not parts:
            return "root"
        if len(parts) == 1:
            return parts[0]
        return "/".join(parts[:2])

    def _resolve_auth_step_url(self, endpoint: Endpoint, asset_map: AssetMap) -> str:
        auth_tokens: tuple[str, ...] = ("auth", "login", "signin", "session", "token", "oauth")
        best_match: Endpoint | None = None
        best_rank = 10_000

        for candidate in asset_map.endpoints:
            if candidate.method.upper() != "POST":
                continue
            lowered = candidate.url_pattern.lower()
            if not any(token in lowered for token in auth_tokens):
                continue

            rank = len([segment for segment in candidate.url_pattern.split("/") if segment])
            if rank < best_rank:
                best_rank = rank
                best_match = candidate

        if best_match is not None:
            return best_match.url_pattern
        return endpoint.url_pattern

    def _resolve_state_change_method(self, endpoint_method: str) -> str:
        normalized = endpoint_method.upper()
        if normalized in {"PUT", "PATCH"}:
            return "PUT"
        return "POST"

    def _resolve_exploit_url(self, url_pattern: str) -> str:
        lowered = url_pattern.lower()
        if "{resource_id}" in lowered or "{id}" in lowered:
            return url_pattern
        normalized = url_pattern.rstrip("/")
        return f"{normalized}/{{resource_id}}"
