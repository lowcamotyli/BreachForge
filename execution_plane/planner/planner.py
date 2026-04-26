from __future__ import annotations

import asyncio
import enum
import importlib
import json
import pkgutil
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from control_plane.codex_analyst import CodexAnalyst
from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from execution_plane.planner.rules import base as base_rule_module
from execution_plane.planner.attack_graph import AttackGraph
from execution_plane.planner.decision_log import DecisionLog, DecisionLogger
from execution_plane.planner.path_ranker import PathRanker
from execution_plane.planner.payload_registry import PayloadRegistry
from execution_plane.planner.playbook_loader import load_builtin_playbooks
from execution_plane.planner.playbooks import AttackPlaybook, PlaybookStep, assert_no_secret_like_data
from storage.db.models import AttackTask, Endpoint, Scan

MAX_TASKS_PER_ENDPOINT = 50
_IDOR_CLASSES: set[str] = {"bola", "tenant_isolation"}
_STATE_CHANGING_METHODS: set[str] = {"POST", "PUT", "DELETE"}
_STRUCTURED_CONTENT_MARKERS: tuple[str, ...] = ("application/json", "+json", "application/problem+json")
_OWNERSHIP_IDENTIFIERS: set[str] = {"owner_id", "user_id", "account_id", "org_id"}
_PRIVILEGE_IDENTIFIERS: set[str] = {"role", "scope", "permission", "user_id", "account_id", "org_id"}
_WORKFLOW_START_MARKERS: tuple[str, ...] = ("create", "start", "begin", "init", "draft", "cart")
_WORKFLOW_FINAL_MARKERS: tuple[str, ...] = ("finalize", "approve", "submit", "confirm", "activate", "pay", "complete")
_ATTACK_CLASS_SEQUENCE_PRIORITY: dict[str, int] = {
    "session_misuse": 0,
    "bola": 1,
    "tenant_isolation": 1,
    "auth_bypass": 2,
    "privilege_escalation": 2,
    "injection": 3,
    "rate_limit_abuse": 4,
    "misconfiguration": 5,
    "sensitive_exposure": 6,
    "workflow_abuse": 8,
}
_UNKNOWN_ATTACK_CLASS_PRIORITY = 7
_SEQUENCE_SCORE_SPREAD = 2.0
_MAX_SEQUENCE_PRIORITY = max(_ATTACK_CLASS_SEQUENCE_PRIORITY.values()) + 1
logger = structlog.get_logger(__name__)


class PlannerState(str, enum.Enum):
    idle = "idle"
    planning = "planning"
    dispatching = "dispatching"
    waiting_feedback = "waiting_feedback"
    replanning = "replanning"


class AttackPlanner:
    def __init__(self, max_tasks_per_endpoint: int = MAX_TASKS_PER_ENDPOINT) -> None:
        self.max_tasks_per_endpoint = max_tasks_per_endpoint
        self.rules: list[AttackRule] = [rule_class() for rule_class in self._discover_rule_classes()]
        self.path_ranker = PathRanker()
        self.payload_registry = PayloadRegistry()
        self.playbooks = load_builtin_playbooks()
        self.decision_logger = DecisionLogger()
        self.codex_analyst = CodexAnalyst()
        self._last_ranked_paths: list[Any] = []
        self._advisory_suggestions: list[dict[str, Any]] = []
        self.state = PlannerState.idle

    def plan(self, context: ScanContext) -> list[AttackTask]:
        self.state = PlannerState.planning
        all_tasks = self._generate_candidate_tasks(context)
        if not all_tasks:
            self.state = PlannerState.idle
            return []

        graph = self._build_attack_graph(context=context, tasks=all_tasks)
        ranked_tasks = self._rank_tasks(graph=graph, tasks=all_tasks)
        self._log_top_ranked_decision(context=context, graph=graph)
        self._suggest_next_actions(context=context, ranked_tasks=ranked_tasks)

        self.state = PlannerState.dispatching
        dispatch_batch = ranked_tasks[:]

        self.state = PlannerState.waiting_feedback
        outcomes = self._observe_outcomes(dispatch_batch)
        if outcomes:
            self.state = PlannerState.replanning
            dispatch_batch = self.replan(graph, outcomes, context=context, candidate_tasks=dispatch_batch)

        self.state = PlannerState.idle
        return dispatch_batch

    def replan(
        self,
        graph_or_context: AttackGraph | ScanContext,
        outcomes: list[dict[str, Any]] | None = None,
        *,
        context: ScanContext | None = None,
        candidate_tasks: list[AttackTask] | None = None,
    ) -> list[AttackTask]:
        # Backward-compatible path: existing callers pass ScanContext only.
        if isinstance(graph_or_context, ScanContext):
            candidates = self.plan(graph_or_context)
            return [task for task in candidates if task.id not in graph_or_context.completed_task_ids]

        graph = graph_or_context
        feedback = outcomes or []
        tasks = candidate_tasks or []
        active_context = context
        if active_context is None:
            return tasks

        failed_actions = {
            str(outcome.get("action"))
            for outcome in feedback
            if str(outcome.get("status", "")).lower() in {"failed", "no_signal", "blocked"}
        }
        completed_task_ids = {
            UUID(str(outcome["task_id"]))
            for outcome in feedback
            if "task_id" in outcome and str(outcome.get("status", "")).lower() in {"done", "completed", "success"}
        }
        active_context.completed_task_ids = active_context.completed_task_ids | completed_task_ids

        filtered_tasks = [
            task
            for task in tasks
            if task.id not in active_context.completed_task_ids and task.attack_class not in failed_actions
        ]
        return self._rank_tasks(graph=graph, tasks=filtered_tasks)

    def _generate_candidate_tasks(self, context: ScanContext) -> list[AttackTask]:
        all_tasks: list[AttackTask] = []
        for endpoint in context.asset_map.endpoints:
            endpoint_tasks: list[AttackTask] = []
            for rule in self.rules:
                if not rule.matches(endpoint, context.asset_map):
                    continue
                generated_tasks = rule.generate_tasks(endpoint, context)
                for task in generated_tasks:
                    self._enrich_task_with_payloads(task=task, endpoint=endpoint)
                    task.priority_score = self._score_task(task, endpoint)
                endpoint_tasks.extend(generated_tasks)
            endpoint_tasks.extend(self._generate_playbook_tasks(endpoint=endpoint, context=context))
            endpoint_tasks.sort(key=lambda task: task.priority_score, reverse=True)
            all_tasks.extend(endpoint_tasks[: self.max_tasks_per_endpoint])
        all_tasks.sort(key=lambda task: task.priority_score, reverse=True)
        return self._sequence_tasks(all_tasks)

    def _build_attack_graph(self, *, context: ScanContext, tasks: list[AttackTask]) -> AttackGraph:
        graph = AttackGraph(scan_id=str(context.scan_id))
        root_id = "scan:start"
        graph.add_node(root_id, endpoint=context.target_url, state="entry", identity="planner")

        for task_index, task in enumerate(tasks):
            node_id = f"task:{task_index}:{task.attack_class}"
            endpoint = self._endpoint_url_by_id(context, task.endpoint_id)
            graph.add_node(
                node_id,
                endpoint=endpoint,
                state=task.attack_class,
                identity=str(task.endpoint_id),
                metadata={"task_ref": task_index, "attack_class": task.attack_class},
            )
            graph.add_edge(
                root_id,
                node_id,
                action=task.attack_class,
                precondition="rule_matches",
                impact=max(0.01, task.priority_score),
                cost=max(0.1, 1.0 - min(task.priority_score, 0.9)),
                metadata={"endpoint_id": str(task.endpoint_id)},
            )
        return graph

    def _rank_tasks(self, *, graph: AttackGraph, tasks: list[AttackTask]) -> list[AttackTask]:
        if not tasks:
            self._last_ranked_paths = []
            return []

        ranked_paths = self.path_ranker.rank_paths(graph=graph, top_k=max(len(tasks) * 3, 10))
        self._last_ranked_paths = ranked_paths
        score_by_task_id: dict[UUID, float] = {}
        score_by_task_ref: dict[int, float] = {}
        for path in ranked_paths:
            terminal_node_id = path.node_ids[-1]
            node = graph.nodes.get(terminal_node_id)
            if node is None:
                continue
            raw_task_ref = node.metadata.get("task_ref")
            if isinstance(raw_task_ref, int):
                existing_ref_score = score_by_task_ref.get(raw_task_ref, 0.0)
                if path.score > existing_ref_score:
                    score_by_task_ref[raw_task_ref] = path.score
                continue

            raw_task_id = node.metadata.get("task_id")
            if isinstance(raw_task_id, str):
                task_id = UUID(raw_task_id)
                existing_score = score_by_task_id.get(task_id, 0.0)
                if path.score > existing_score:
                    score_by_task_id[task_id] = path.score

        for task_index, task in enumerate(tasks):
            graph_score = score_by_task_ref.get(task_index)
            if graph_score is None and task.id is not None:
                graph_score = score_by_task_id.get(task.id, 0.0)
            task.priority_score = task.priority_score + (graph_score or 0.0)

        return sorted(tasks, key=lambda task: task.priority_score, reverse=True)

    def _endpoint_url_by_id(self, context: ScanContext, endpoint_id: UUID) -> str:
        for endpoint in context.asset_map.endpoints:
            if endpoint.id == endpoint_id:
                return endpoint.url_pattern
        return ""

    def _observe_outcomes(self, dispatched_tasks: list[AttackTask]) -> list[dict[str, Any]]:
        # Planner runs before worker execution in this phase, so feedback can be injected later.
        _ = dispatched_tasks
        return []

    def _score_task(self, task: AttackTask, endpoint: Endpoint) -> float:
        score = 0.0
        if task.attack_class in _IDOR_CLASSES:
            score += 0.40
        if endpoint.auth_required:
            score += 0.20
        if endpoint.method.upper() in _STATE_CHANGING_METHODS:
            score += 0.15
        if self._has_ownership_params(endpoint):
            score += 0.15
        score += 0.10
        return score

    def _has_ownership_params(self, endpoint: Endpoint) -> bool:
        lower_url = endpoint.url_pattern.lower()
        if any(identifier in lower_url for identifier in _OWNERSHIP_IDENTIFIERS):
            return True
        for parameter in endpoint.parameters:
            raw_name = parameter.get("name")
            if isinstance(raw_name, str) and raw_name.lower() in _OWNERSHIP_IDENTIFIERS:
                return True
        return False

    def _sequence_tasks(self, tasks: list[AttackTask]) -> list[AttackTask]:
        def _class_priority(task: AttackTask) -> int:
            return _ATTACK_CLASS_SEQUENCE_PRIORITY.get(task.attack_class, _UNKNOWN_ATTACK_CLASS_PRIORITY)

        sequenced = sorted(tasks, key=_class_priority)
        for task in sequenced:
            class_priority = _class_priority(task)
            task.priority_score = ((_MAX_SEQUENCE_PRIORITY - class_priority) * _SEQUENCE_SCORE_SPREAD) + task.priority_score
        return sequenced

    def _enrich_task_with_payloads(self, *, task: AttackTask, endpoint: Endpoint) -> None:
        payload_context = {
            "method": endpoint.method,
            "url_pattern": endpoint.url_pattern,
            "target_parameter": task.target_parameter or "",
            "content_type": endpoint.observed_content_type or "",
        }
        payload_candidates = self.payload_registry.get_payloads(task.attack_class, context=payload_context)
        safe_payloads = self.payload_registry.safety_filter(payload_candidates)
        if not safe_payloads:
            return

        try:
            parsed = json.loads(task.hypothesis)
            if isinstance(parsed, dict):
                existing_payloads_raw = parsed.get("payload_candidates")
                existing_payloads = existing_payloads_raw if isinstance(existing_payloads_raw, list) else []
                parsed["payload_candidates"] = self.payload_registry.safety_filter(
                    [*existing_payloads, *safe_payloads]
                )
                task.hypothesis = json.dumps(parsed, sort_keys=True)
                return
        except (TypeError, ValueError, json.JSONDecodeError):
            pass

        task.hypothesis = json.dumps(
            {
                "hypothesis": task.hypothesis,
                "payload_candidates": safe_payloads,
            },
            sort_keys=True,
        )

    def _generate_playbook_tasks(self, *, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        tasks: list[AttackTask] = []
        for playbook in self.playbooks:
            matched, reason = self._playbook_matches_endpoint(playbook=playbook, endpoint=endpoint, context=context)
            if not matched:
                continue
            self._log_playbook_selection(context=context, playbook=playbook, endpoint=endpoint, reason=reason)
            tasks.extend(
                self._tasks_from_playbook(
                    playbook=playbook,
                    endpoint=endpoint,
                    context=context,
                    selection_reason=reason,
                )
            )
        return tasks

    def _tasks_from_playbook(
        self,
        *,
        playbook: AttackPlaybook,
        endpoint: Endpoint,
        context: ScanContext,
        selection_reason: str,
    ) -> list[AttackTask]:
        target_parameter = self._target_parameter_for_playbook(endpoint=endpoint, playbook=playbook)
        tasks: list[AttackTask] = []
        prerequisites: list[str] = []
        for step_index, step in enumerate(playbook.steps, start=1):
            step_name = step.id if isinstance(step.id, str) and step.id else step.action
            step_id = f"{playbook.id}:{step_index}:{step_name}"
            hypothesis_payload = {
                "action": step.action,
                "expected_signal": step.expected_signal,
                "identity_selector": step.identity_selector,
                "observe_only": step.observe_only,
                "playbook_id": playbook.id,
                "probe_template": step.probe_template,
                "safety_budget": playbook.safety_budget,
                "selection_reason": selection_reason,
                "step_id": step_id,
                "validator": step.validator,
            }
            assert_no_secret_like_data(hypothesis_payload, path="decision_payload")
            hypothesis = json.dumps(hypothesis_payload, sort_keys=True)
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=playbook.attack_class,
                    target_parameter=target_parameter,
                    hypothesis=hypothesis,
                    priority_score=self._score_playbook_step(playbook=playbook, step=step, endpoint=endpoint),
                    prerequisites=prerequisites[:] or None,
                    step_order=step_index,
                )
            )
            self._log_playbook_step(context=context, playbook=playbook, step_id=step_id, step=step)
            prerequisites.append(step_id)
        return tasks

    def _playbook_matches_endpoint(
        self,
        *,
        playbook: AttackPlaybook,
        endpoint: Endpoint,
        context: ScanContext,
    ) -> tuple[bool, str]:
        reasons = self._playbook_candidate_reasons(playbook=playbook, endpoint=endpoint, context=context)
        if not reasons:
            return False, "no explainable signal or heuristic matched this playbook"

        preconditions = playbook.preconditions
        method = endpoint.method.upper()
        methods = preconditions.get("methods")
        if isinstance(methods, list) and method not in {str(value).upper() for value in methods}:
            return False, f"method {method} not in playbook methods"

        auth_required = preconditions.get("auth_required")
        if isinstance(auth_required, bool) and endpoint.auth_required is not auth_required:
            return False, "auth_required precondition did not match"

        path_contains_any = _string_list(preconditions.get("path_contains_any"))
        if path_contains_any and not _contains_any(endpoint.url_pattern, path_contains_any):
            return False, "path markers did not match"

        parameter_contains_any = _string_list(preconditions.get("parameter_name_contains_any"))
        if parameter_contains_any and not self._endpoint_has_parameter_marker(endpoint, parameter_contains_any):
            return False, "parameter markers did not match"

        if preconditions.get("structured_response") is True and not self._endpoint_returns_structured_data(endpoint):
            return False, "structured response precondition did not match"

        if preconditions.get("requires_related_start_step") is True and not self._has_related_workflow_start_step(
            endpoint=endpoint,
            asset_map=context.asset_map,
        ):
            return False, "related workflow start step was not found"

        return True, self._playbook_match_reason(playbook=playbook, endpoint=endpoint, reasons=reasons)

    def _playbook_candidate_reasons(
        self,
        *,
        playbook: AttackPlaybook,
        endpoint: Endpoint,
        context: ScanContext,
    ) -> list[str]:
        reasons: list[str] = []
        playbook_signals = self._asset_map_playbook_signals(context.asset_map)
        if playbook.id in playbook_signals or playbook.attack_class in playbook_signals:
            reasons.append("asset_map_signal")

        method = endpoint.method.upper()
        has_id_path = "{id" in endpoint.url_pattern.lower() or "{user_id" in endpoint.url_pattern.lower()
        if playbook.id == "bola_idor" and endpoint.auth_required and method == "GET" and (
            has_id_path or self._endpoint_has_parameter_marker(endpoint, ["id", "user_id", "account_id"])
        ):
            reasons.append("heuristic:auth_get_with_identifier")

        if playbook.id == "privilege_drift" and self._endpoint_has_parameter_marker(
            endpoint, list(_PRIVILEGE_IDENTIFIERS)
        ):
            reasons.append("heuristic:privilege_parameter_marker")

        if playbook.id == "workflow_abuse" and method in {"POST", "PUT", "PATCH"} and (
            _contains_any(endpoint.url_pattern, list(_WORKFLOW_FINAL_MARKERS))
            or self._has_related_workflow_start_step(endpoint=endpoint, asset_map=context.asset_map)
        ):
            reasons.append("heuristic:workflow_transition")

        if playbook.id == "secret_to_impact" and (
            self._endpoint_returns_structured_data(endpoint) or self._asset_map_has_secret_modules(context.asset_map)
        ):
            reasons.append("heuristic:structured_or_secret_signal")
        return reasons

    def _asset_map_playbook_signals(self, asset_map: AssetMap) -> set[str]:
        raw_signals = getattr(asset_map, "signals", None)
        if raw_signals is None:
            raw_signals = getattr(asset_map, "planning_signals", None)
        if raw_signals is None:
            return set()

        if isinstance(raw_signals, dict):
            values: list[Any] = []
            for key in ("attack_playbooks", "playbook_candidates", "attack_classes"):
                raw_value = raw_signals.get(key)
                if isinstance(raw_value, list):
                    values.extend(raw_value)
                elif isinstance(raw_value, str):
                    values.append(raw_value)
            return {str(value).strip() for value in values if str(value).strip()}

        if isinstance(raw_signals, list):
            return {str(value).strip() for value in raw_signals if str(value).strip()}
        return set()

    def _playbook_match_reason(self, *, playbook: AttackPlaybook, endpoint: Endpoint, reasons: list[str]) -> str:
        return (
            f"playbook={playbook.id}; attack_class={playbook.attack_class}; "
            f"method={endpoint.method.upper()}; path={endpoint.url_pattern}; reasons={','.join(sorted(reasons))}"
        )

    def _endpoint_has_parameter_marker(self, endpoint: Endpoint, markers: list[str]) -> bool:
        names: list[str] = []
        for parameter in endpoint.parameters:
            raw_name = parameter.get("name") if isinstance(parameter, dict) else None
            if isinstance(raw_name, str):
                names.append(raw_name)
        names.append(endpoint.url_pattern)
        return any(marker.lower() in name.lower() for marker in markers for name in names)

    def _endpoint_returns_structured_data(self, endpoint: Endpoint) -> bool:
        content_type = (endpoint.observed_content_type or "").lower()
        if any(marker in content_type for marker in _STRUCTURED_CONTENT_MARKERS):
            return True
        if endpoint.url_pattern.lower().endswith(".json"):
            return True
        for parameter in endpoint.parameters:
            if isinstance(parameter, dict) and str(parameter.get("type") or "").lower() in {"object", "array"}:
                return True
        return False

    def _has_related_workflow_start_step(self, *, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        endpoint_resource = self._workflow_resource_key(endpoint.url_pattern)
        for candidate in asset_map.endpoints:
            if candidate.id == endpoint.id:
                continue
            if self._workflow_resource_key(candidate.url_pattern) != endpoint_resource:
                continue
            if _contains_any(candidate.url_pattern, list(_WORKFLOW_START_MARKERS)):
                return True
        return False

    def _asset_map_has_secret_modules(self, asset_map: AssetMap) -> bool:
        raw_signals = getattr(asset_map, "signals", None)
        if isinstance(raw_signals, dict):
            for key in ("secret_modules", "structured_responses", "secret_signals", "modules"):
                value = raw_signals.get(key)
                if isinstance(value, list) and value:
                    return True
                if isinstance(value, bool) and value:
                    return True
        return False

    def _workflow_resource_key(self, url_pattern: str) -> str:
        parts = [segment for segment in url_pattern.strip("/").split("/") if segment and not segment.startswith("{")]
        if not parts:
            return "root"
        return "/".join(parts[:2]) if len(parts) > 1 else parts[0]

    def _target_parameter_for_playbook(self, *, endpoint: Endpoint, playbook: AttackPlaybook) -> str | None:
        markers = _string_list(playbook.preconditions.get("parameter_name_contains_any"))
        for parameter in endpoint.parameters:
            if not isinstance(parameter, dict):
                continue
            raw_name = parameter.get("name")
            if not isinstance(raw_name, str) or not raw_name.strip():
                continue
            if not markers or any(marker.lower() in raw_name.lower() for marker in markers):
                return raw_name.strip()
        return "response" if playbook.attack_class == "sensitive_exposure" else None

    def _score_playbook_step(self, *, playbook: AttackPlaybook, step: PlaybookStep, endpoint: Endpoint) -> float:
        task = AttackTask(
            scan_id=endpoint.asset_map_id,
            endpoint_id=endpoint.id,
            attack_class=playbook.attack_class,
            target_parameter=None,
            hypothesis=step.expected_signal,
        )
        score = self._score_task(task, endpoint)
        if step.observe_only:
            score -= 0.05
        return max(0.01, score)

    def _log_playbook_selection(
        self,
        *,
        context: ScanContext,
        playbook: AttackPlaybook,
        endpoint: Endpoint,
        reason: str,
    ) -> None:
        alternatives = [candidate.id for candidate in self.playbooks if candidate.id != playbook.id]
        self.decision_logger.log(
            DecisionLog(
                scan_id=str(context.scan_id),
                timestamp=datetime.now(timezone.utc),
                step_id=f"playbook:{playbook.id}:selected",
                chosen_action=playbook.attack_class,
                rationale=reason,
                alternatives=alternatives[:3],
                status="selected",
                reason=f"endpoint {endpoint.method.upper()} {endpoint.url_pattern} satisfied playbook preconditions",
            )
        )

    def _log_playbook_step(
        self,
        *,
        context: ScanContext,
        playbook: AttackPlaybook,
        step_id: str,
        step: PlaybookStep,
    ) -> None:
        self.decision_logger.log(
            DecisionLog(
                scan_id=str(context.scan_id),
                timestamp=datetime.now(timezone.utc),
                step_id=step_id,
                chosen_action=step.action,
                rationale=f"validator={step.validator}; observe_only={step.observe_only}; max_attempts={step.max_attempts}",
                alternatives=[],
                status="planned",
                reason=f"planned from playbook {playbook.id}",
            )
        )

    def _log_top_ranked_decision(self, *, context: ScanContext, graph: AttackGraph) -> None:
        if not self._last_ranked_paths:
            return

        top_path = self._last_ranked_paths[0]
        terminal_node_id = top_path.node_ids[-1]
        terminal_node = graph.nodes.get(terminal_node_id)
        if terminal_node is None:
            return

        chosen_action = str(terminal_node.metadata.get("attack_class") or terminal_node.state or "unknown")
        alternatives: list[str] = []
        for path in self._last_ranked_paths[1:4]:
            alt_node = graph.nodes.get(path.node_ids[-1])
            if alt_node is None:
                continue
            alt_action = str(alt_node.metadata.get("attack_class") or alt_node.state or "unknown")
            if alt_action not in alternatives:
                alternatives.append(alt_action)

        rationale = (
            f"path_score={top_path.score:.4f}; "
            f"path_nodes={len(top_path.node_ids)}; "
            f"terminal_node={terminal_node_id}"
        )
        self.decision_logger.log(
            DecisionLog(
                scan_id=str(context.scan_id),
                timestamp=datetime.now(timezone.utc),
                step_id="path_ranking",
                chosen_action=chosen_action,
                rationale=rationale,
                alternatives=alternatives,
            )
        )

    def _suggest_next_actions(self, *, context: ScanContext, ranked_tasks: list[AttackTask]) -> None:
        try:
            candidate_actions = list(dict.fromkeys(task.attack_class for task in ranked_tasks[:10]))
            asset_map_summary = {
                "endpoints": [
                    {"url_pattern": endpoint.url_pattern, "method": endpoint.method}
                    for endpoint in context.asset_map.endpoints
                ]
            }
            self._advisory_suggestions = self.codex_analyst.suggest_next_actions(
                asset_map_summary=asset_map_summary,
                probe_history=[],
                step_context={"candidate_actions": candidate_actions},
            )
        except Exception:
            pass

    def _discover_rule_classes(self) -> list[type[AttackRule]]:
        rules_package = importlib.import_module("execution_plane.planner.rules")
        for module_info in pkgutil.iter_modules(rules_package.__path__):
            if module_info.name.startswith("_") or module_info.name == "base":
                continue
            importlib.import_module(f"{rules_package.__name__}.{module_info.name}")
        classes: list[type[AttackRule]] = []
        for subclass in _walk_subclasses(AttackRule):
            if subclass.__module__ == base_rule_module.__name__:
                continue
            classes.append(subclass)
        classes.sort(key=lambda rule_class: (rule_class.__module__, rule_class.__name__))
        return classes


def _walk_subclasses(base_class: type[AttackRule]) -> list[type[AttackRule]]:
    discovered: list[type[AttackRule]] = []
    for subclass in base_class.__subclasses__():
        discovered.append(subclass)
        discovered.extend(_walk_subclasses(subclass))
    return discovered


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _contains_any(value: str, needles: list[str]) -> bool:
    lowered = value.lower()
    return any(needle.lower() in lowered for needle in needles)


def plan_attack(scan_id: str, asset_map: dict[str, Any]) -> None:
    """RQ-callable entrypoint for attack planning."""
    asyncio.run(_plan_attack_async(scan_id=scan_id, asset_map=asset_map))


async def _plan_attack_async(scan_id: str, asset_map: dict[str, Any]) -> None:
    from storage.db.session import AsyncSessionLocal

    scan_uuid = UUID(scan_id)
    async with AsyncSessionLocal() as session:
        scan_record = await _load_scan_with_asset_map(session=session, scan_id=scan_uuid)
        if scan_record is None or scan_record.asset_map is None:
            logger.warning("planner_scan_or_asset_map_missing", scan_id=scan_id)
            return

        endpoints = list(scan_record.asset_map.endpoints)
        target_url = _resolve_target_url(asset_map=asset_map, scan=scan_record)
        scan_context = ScanContext(scan_id=scan_uuid, target_url=target_url, asset_map=scan_record.asset_map)

        planner = AttackPlanner()
        tasks = planner.plan(scan_context)
        session.add_all(tasks)
        await session.commit()
        try:
            import os
            from redis import Redis
            from rq import Queue as RQueue
            _redis_url = os.getenv("REDIS_URL")
            if _redis_url:
                _conn = Redis.from_url(_redis_url)
                _q = RQueue(name=os.getenv("RQ_ATTACK_QUEUE", "attack_planning"), connection=_conn)
                _q.enqueue("execution_plane.workers.dispatcher.dispatch_attack_tasks", scan_id)
                logger.info("attack_dispatch_enqueued", scan_id=scan_id, task_count=len(tasks))
        except Exception as _exc:
            logger.exception("attack_dispatch_enqueue_failed", scan_id=scan_id, error=str(_exc))

        logger.info("planner_tasks_persisted", scan_id=scan_id, endpoint_count=len(endpoints), task_count=len(tasks))


async def _load_scan_with_asset_map(*, session: Any, scan_id: UUID) -> Scan | None:
    statement = (
        select(Scan)
        .options(selectinload(Scan.target), selectinload(Scan.asset_map).selectinload(AssetMap.endpoints))
        .where(Scan.id == scan_id)
    )
    result = await session.execute(statement)
    return result.scalar_one_or_none()


def _resolve_target_url(*, asset_map: dict[str, Any], scan: Scan) -> str:
    target_url = asset_map.get("target_url")
    if isinstance(target_url, str) and target_url:
        return target_url

    if scan.target is not None and isinstance(scan.target.url, str):
        return scan.target.url
    return ""
