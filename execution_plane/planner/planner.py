from __future__ import annotations

import asyncio
import enum
import hashlib
import importlib
import inspect
import json
import os
import pkgutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from api.middleware.logging import redact_for_audit
from api.models.requests import ScanPolicy
from control_plane.codex_analyst import CodexAnalyst
from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from execution_plane.planner.rules import base as base_rule_module
from execution_plane.planner.attack_graph import AttackGraph
from execution_plane.planner.decision_log import DecisionLog, DecisionLogger, FeedbackPayload, TaskOutcome
from execution_plane.planner.path_ranker import PathRanker
from execution_plane.planner.payload_registry import PayloadRegistry
from execution_plane.planner.playbook_loader import load_builtin_playbooks
from execution_plane.planner.playbooks import AttackPlaybook, PlaybookStep, assert_no_secret_like_data
from storage.db.models import AttackTask, AttackTaskStatus, AuditEvent, AuditEventType, Endpoint, Scan

if TYPE_CHECKING:
    from control_plane.auth_manager import IdentityContext

MAX_TASKS_PER_ENDPOINT = 50
MAX_REPLAN_ROUNDS = 5
MAX_REPLAN_TASKS_PER_JOB = 10
_IDOR_CLASSES: set[str] = {"bola", "tenant_isolation"}
_STATE_CHANGING_METHODS: set[str] = {"POST", "PUT", "DELETE"}
_POLICY_MUTATING_METHODS: set[str] = {"POST", "PUT", "PATCH", "DELETE"}
_READ_AFTER_WRITE_METHODS: set[str] = {"POST", "PUT", "PATCH"}
_READ_AFTER_WRITE_ATTACK_CLASSES: set[str] = {
    "workflow_abuse",
    "bola",
    "tenant_isolation",
    "privilege_escalation",
    "mass_assignment",
    "business_logic",
}
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
    "bfla": 2,
    "injection": 3,
    "rate_limit_abuse": 4,
    "misconfiguration": 5,
    "sensitive_exposure": 6,
    "ssrf": 6,
    "mass_assignment": 6,
    "oauth_redirect": 6,
    "oauth_state_csrf": 6,
    "oauth_token_reuse": 6,
    "excessive_exposure": 6,
    "workflow_abuse": 8,
}
_UNKNOWN_ATTACK_CLASS_PRIORITY = 7
_SEQUENCE_SCORE_SPREAD = 2.0
_MAX_SEQUENCE_PRIORITY = max(_ATTACK_CLASS_SEQUENCE_PRIORITY.values()) + 1
logger = structlog.get_logger(__name__)


@dataclass
class ReplanBudget:
    scan_id: str
    rounds_used: int = 0
    max_rounds_per_scan: int = 3
    rounds_per_class: dict[str, int] = field(default_factory=dict)
    max_rounds_per_class: int = 2
    rounds_per_endpoint: dict[str, int] = field(default_factory=dict)
    max_rounds_per_endpoint: int = 2

    def budget_exceeded(self, attack_class: str | None = None, endpoint_id: str | None = None) -> bool:
        if self.rounds_used >= self.max_rounds_per_scan:
            return True
        if attack_class and self.rounds_per_class.get(attack_class, 0) >= self.max_rounds_per_class:
            return True
        if endpoint_id and self.rounds_per_endpoint.get(endpoint_id, 0) >= self.max_rounds_per_endpoint:
            return True
        return False

    def increment(self, attack_class: str | None = None, endpoint_id: str | None = None) -> None:
        self.rounds_used += 1
        if attack_class:
            self.rounds_per_class[attack_class] = self.rounds_per_class.get(attack_class, 0) + 1
        if endpoint_id:
            self.rounds_per_endpoint[endpoint_id] = self.rounds_per_endpoint.get(endpoint_id, 0) + 1


@dataclass
class ScanBudget:
    max_requests: int
    max_runtime_seconds: int
    per_class_cap: dict[str, int]
    priority_classes: list[str]
    requests_dispatched: int = 0

    def allows_dispatch(self, task: AttackTask) -> bool:
        if self.max_requests <= 0:
            return True
        if self.requests_dispatched < self.max_requests:
            return True
        return str(task.attack_class) in self.priority_classes

    def consume(self) -> None:
        self.requests_dispatched += 1

    @property
    def remaining_requests(self) -> int:
        return max(self.max_requests - self.requests_dispatched, 0)


class PlannerState(str, enum.Enum):
    idle = "idle"
    planning = "planning"
    dispatching = "dispatching"
    waiting_feedback = "waiting_feedback"
    replanning = "replanning"


class AttackPlanner:
    def __init__(self, max_tasks_per_endpoint: int = MAX_TASKS_PER_ENDPOINT, production_safe_mode: bool = False) -> None:
        self.max_tasks_per_endpoint = max_tasks_per_endpoint
        self.production_safe_mode = production_safe_mode
        self.rules: list[AttackRule] = [rule_class() for rule_class in self._discover_rule_classes()]
        self.path_ranker = PathRanker()
        self.payload_registry = PayloadRegistry()
        self.playbooks = load_builtin_playbooks()
        self.decision_logger = DecisionLogger()
        self.codex_analyst = CodexAnalyst()
        self._last_ranked_paths: list[Any] = []
        self._advisory_suggestions: list[dict[str, Any]] = []
        self.state = PlannerState.idle

    def plan(
        self,
        context: ScanContext,
        unauth_mode: bool = False,
        identity_matrix: dict[str, IdentityContext] | None = None,
        scan_budget: ScanBudget | None = None,
    ) -> list[AttackTask]:
        self.state = PlannerState.planning
        rules = self.rules
        if unauth_mode:
            filtered_rules: list[AttackRule] = []
            for rule in rules:
                if getattr(rule, "requires_auth", False):
                    logger.debug("unauth_mode: skipping requires_auth rule", rule=rule.name)
                    continue
                filtered_rules.append(rule)
            rules = filtered_rules

        all_tasks = self._generate_candidate_tasks(context, rules, identity_matrix=identity_matrix)
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

        if scan_budget is not None:
            dispatch_batch = self._apply_scan_budget(dispatch_batch, scan_budget=scan_budget)
        self.state = PlannerState.idle
        return dispatch_batch

    def _apply_scan_budget(self, tasks: list[AttackTask], *, scan_budget: ScanBudget) -> list[AttackTask]:
        budgeted: list[AttackTask] = []
        for task in tasks:
            if not scan_budget.allows_dispatch(task):
                continue
            budgeted.append(task)
            scan_budget.consume()
        return budgeted

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
            if graph_or_context.replan_budget is None:
                graph_or_context.replan_budget = ReplanBudget(scan_id=str(graph_or_context.scan_id))
            if graph_or_context.replan_budget.budget_exceeded():
                return []
            graph_or_context.replan_budget.increment()
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

    def _generate_candidate_tasks(
        self,
        context: ScanContext,
        rules: list[AttackRule] | None = None,
        identity_matrix: dict[str, IdentityContext] | None = None,
    ) -> list[AttackTask]:
        all_tasks: list[AttackTask] = []
        active_rules = rules or self.rules
        for endpoint in context.asset_map.endpoints:
            endpoint_tasks: list[AttackTask] = []
            for rule in active_rules:
                if not rule.matches(endpoint, context.asset_map):
                    continue
                generated_tasks = self._generate_rule_tasks(
                    rule=rule,
                    endpoint=endpoint,
                    context=context,
                    identity_matrix=identity_matrix,
                )
                for task in generated_tasks:
                    self._apply_read_after_write_plan(task=task, endpoint=endpoint)
                    self._enrich_task_with_payloads(task=task, endpoint=endpoint)
                    task.priority_score = self._score_task(task, endpoint)
                endpoint_tasks.extend(generated_tasks)
            endpoint_tasks.extend(self._generate_playbook_tasks(endpoint=endpoint, context=context))
            endpoint_tasks.sort(key=lambda task: task.priority_score, reverse=True)
            all_tasks.extend(endpoint_tasks[: self.max_tasks_per_endpoint])
        all_tasks.sort(key=lambda task: task.priority_score, reverse=True)
        return self._sequence_tasks(all_tasks)

    def _generate_rule_tasks(
        self,
        *,
        rule: AttackRule,
        endpoint: Endpoint,
        context: ScanContext,
        identity_matrix: dict[str, IdentityContext] | None,
    ) -> list[AttackTask]:
        identity_pairs = self._identity_pairs_for_rule(rule=rule, identity_matrix=identity_matrix)
        parameters = inspect.signature(rule.generate_tasks).parameters
        if "identity_pairs" in parameters:
            generated = rule.generate_tasks(endpoint, context, identity_pairs=identity_pairs)
        else:
            generated = rule.generate_tasks(endpoint, context)
        if not identity_pairs or rule.attack_class not in {"bola", "tenant_isolation", "privilege_escalation"}:
            return generated
        return self._expand_differential_pairs(generated)

    def _identity_pairs_for_rule(
        self,
        *,
        rule: AttackRule,
        identity_matrix: dict[str, IdentityContext] | None,
    ) -> list[tuple[str, str]] | None:
        if rule.attack_class not in {"bola", "tenant_isolation", "privilege_escalation"}:
            return None
        if not identity_matrix or len(identity_matrix) < 2:
            return None

        identities: list[tuple[str, IdentityContext]] = []
        for index, (identity_name, identity_context) in enumerate(identity_matrix.items()):
            candidate_name = identity_name.strip() or identity_context.name.strip() or f"identity_{index + 1}"
            identities.append((candidate_name, identity_context))
        if len(identities) < 2:
            return None

        if rule.attack_class == "bola":
            owner_name = identities[0][0]
            return [(owner_name, attacker_name) for attacker_name, _ in identities[1:]]

        if rule.attack_class == "tenant_isolation":
            pairs: list[tuple[str, str]] = []
            for owner_name, owner_context in identities:
                owner_tenant = (owner_context.tenant_hint or "").strip().lower()
                if not owner_tenant:
                    continue
                for attacker_name, attacker_context in identities:
                    if owner_name == attacker_name:
                        continue
                    attacker_tenant = (attacker_context.tenant_hint or "").strip().lower()
                    if not attacker_tenant or attacker_tenant == owner_tenant:
                        continue
                    pairs.append((owner_name, attacker_name))
            return pairs or None

        high_privilege_names: list[str] = []
        low_privilege_names: list[str] = []
        for identity_name, identity_context in identities:
            raw_role = getattr(identity_context.role, "value", identity_context.role)
            role_hint = str(raw_role).strip().lower()
            if role_hint in {"admin", "superuser"}:
                high_privilege_names.append(identity_name)
            else:
                low_privilege_names.append(identity_name)
        if not high_privilege_names or not low_privilege_names:
            return None
        return [(owner_name, attacker_name) for owner_name in high_privilege_names for attacker_name in low_privilege_names]

    def _expand_differential_pairs(self, tasks: list[AttackTask]) -> list[AttackTask]:
        paired_tasks: list[AttackTask] = []
        for attacker_task in tasks:
            attacker_hypothesis = self._parse_hypothesis_config(attacker_task.hypothesis)
            owner_identity = str(attacker_hypothesis.get("owner_identity") or "").strip()
            attacker_identity = str(attacker_hypothesis.get("identity_selector") or "").strip()
            is_differential_probe = bool(attacker_hypothesis.get("differential_probe"))
            if not (owner_identity and attacker_identity and is_differential_probe):
                paired_tasks.append(attacker_task)
                continue

            owner_hypothesis = dict(attacker_hypothesis)
            owner_hypothesis["identity_selector"] = owner_identity
            owner_hypothesis["owner_identity"] = owner_identity
            owner_task = AttackTask(
                scan_id=attacker_task.scan_id,
                endpoint_id=attacker_task.endpoint_id,
                attack_class=attacker_task.attack_class,
                target_parameter=attacker_task.target_parameter,
                hypothesis=json.dumps(owner_hypothesis, sort_keys=True),
            )
            paired_tasks.append(owner_task)
            paired_tasks.append(attacker_task)
        return paired_tasks

    def _parse_hypothesis_config(self, hypothesis: str) -> dict[str, Any]:
        try:
            parsed = json.loads(hypothesis)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {"hypothesis": hypothesis}
        if isinstance(parsed, dict):
            return parsed
        return {"hypothesis": hypothesis}

    def _build_read_after_write_chain(
        self,
        mutation_step: dict[str, Any],
        endpoint_url: str,
        extract_field: str | None = None,
    ) -> list[dict[str, Any]]:
        mutation_step_payload = dict(mutation_step)
        follow_up_url = endpoint_url
        if extract_field:
            mutation_step_payload["extract"] = {extract_field: "id"}
            follow_up_url = f"{endpoint_url.rstrip('/')}/{{{extract_field}}}"
        follow_up_step = {
            "method": "GET",
            "url_pattern": follow_up_url,
            "probe_type": "read_after_write",
            "extract": None,
        }
        return [mutation_step_payload, follow_up_step]

    def _should_plan_read_after_write(self, attack_class: str, method: str) -> bool:
        return method.upper() in _READ_AFTER_WRITE_METHODS and attack_class in _READ_AFTER_WRITE_ATTACK_CLASSES

    def _apply_read_after_write_plan(self, *, task: AttackTask, endpoint: Endpoint) -> None:
        method = endpoint.method.upper()
        if not self._should_plan_read_after_write(task.attack_class, method):
            return

        hypothesis_config = self._parse_hypothesis_config(task.hypothesis)
        if "chain_steps" in hypothesis_config:
            return

        mutation_step: dict[str, Any] = {
            "method": method,
            "url_pattern": endpoint.url_pattern,
            "probe_type": "mutation",
            "extract": None,
        }

        extract_field: str | None = None
        if method == "POST":
            extract_field = "item_id"

        chain_steps = self._build_read_after_write_chain(
            mutation_step=mutation_step,
            endpoint_url=endpoint.url_pattern,
            extract_field=extract_field,
        )
        if getattr(self, "production_safe_mode", False):
            chain_steps = chain_steps[1:]

        hypothesis_config["chain_steps"] = chain_steps
        hypothesis_config["read_after_write"] = True
        task.hypothesis = json.dumps(hypothesis_config, sort_keys=True)

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

        if playbook.attack_class == "ssrf" and self._endpoint_has_parameter_marker(
            endpoint,
            ["url", "uri", "endpoint", "callback", "redirect", "webhook", "src", "href", "fetch", "load", "file"],
        ):
            reasons.append("heuristic:ssrf_url_accepting_parameter")
        if playbook.id == "mass_assignment_probe" and method in {"PUT", "PATCH"} and self._endpoint_returns_structured_data(
            endpoint
        ):
            reasons.append("heuristic:structured_write_endpoint")
        if playbook.id == "bfla_admin_function" and endpoint.auth_required and _contains_any(
            endpoint.url_pattern,
            ["/admin", "/internal", "/management", "/superuser", "/ops", "/system"],
        ):
            reasons.append("heuristic:admin_function_path")
        if playbook.id == "bfla_http_verb" and endpoint.auth_required and method in {"DELETE", "PUT", "PATCH"}:
            reasons.append("heuristic:restricted_mutating_verb")
        if playbook.id == "excessive_data_exposure" and method == "GET" and self._endpoint_returns_structured_data(
            endpoint
        ):
            reasons.append("heuristic:structured_read_endpoint")
        if playbook.attack_class in {"oauth_redirect", "oauth_state_csrf", "oauth_token_reuse"} and (
            _contains_any(endpoint.url_pattern, ["/oauth", "/authorize", "/authorization", "/token", "/logout", "/revoke"])
            or self._endpoint_has_parameter_marker(
                endpoint,
                ["redirect_uri", "state", "response_type", "access_token", "refresh_token", "authorization"],
            )
        ):
            reasons.append("heuristic:oauth_flow_marker")
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
        _rules_pkg = rules_package.__name__ + "."
        classes: list[type[AttackRule]] = []
        for subclass in _walk_subclasses(AttackRule):
            if not subclass.__module__.startswith(_rules_pkg):
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


def filter_tasks_by_policy(tasks: list[AttackTask], policy: ScanPolicy) -> tuple[list[AttackTask], list[tuple[AttackTask, str]]]:
    allowed_tasks: list[AttackTask] = []
    skipped_tasks: list[tuple[AttackTask, str]] = []
    allowed_domains = {domain.strip().lower() for domain in policy.allowed_domains if domain.strip()}

    for task in tasks:
        endpoint = getattr(task, "endpoint", None)
        method = str(getattr(endpoint, "method", "") or "").upper()
        url = str(getattr(endpoint, "url_pattern", "") or "")

        if method in _POLICY_MUTATING_METHODS and not policy.mutating_allowed:
            skipped_tasks.append((task, "mutating_allowed"))
            continue

        parsed_url = urlparse(url)
        hostname = (parsed_url.hostname or "").lower()
        if allowed_domains and hostname and hostname not in allowed_domains:
            skipped_tasks.append((task, "allowed_domains"))
            continue

        allowed_tasks.append(task)

    return allowed_tasks, skipped_tasks


def plan_attack(scan_id: str, asset_map: dict[str, Any]) -> None:
    """RQ-callable entrypoint for attack planning."""
    asyncio.run(_plan_attack_async(scan_id=scan_id, asset_map=asset_map))


def _feedback_payload_from_dict(feedback_payload_dict: dict[str, Any]) -> FeedbackPayload:
    outcome_raw = feedback_payload_dict.get("outcome", TaskOutcome.no_signal.value)
    try:
        outcome = TaskOutcome(str(outcome_raw))
    except ValueError:
        outcome = TaskOutcome.no_signal
    return FeedbackPayload(
        outcome=outcome,
        scan_id=str(feedback_payload_dict.get("scan_id", "")),
        task_id=str(feedback_payload_dict.get("task_id", "")),
        endpoint=str(feedback_payload_dict.get("endpoint", "")),
        finding_class=str(feedback_payload_dict.get("finding_class", "")),
        confidence=float(feedback_payload_dict.get("confidence", 0.0)),
        follow_up_hints=[str(hint) for hint in feedback_payload_dict.get("follow_up_hints", []) if isinstance(hint, str)],
        parent_evidence_ref=(
            str(feedback_payload_dict["parent_evidence_ref"])
            if feedback_payload_dict.get("parent_evidence_ref") is not None
            else None
        ),
        metadata=feedback_payload_dict.get("metadata", {}) if isinstance(feedback_payload_dict.get("metadata"), dict) else {},
    )


def _select_followup_playbook(feedback: FeedbackPayload) -> str | None:
    hints = {hint.strip().lower() for hint in feedback.follow_up_hints if isinstance(hint, str)}
    finding_class = feedback.finding_class.strip().lower()
    outcome = getattr(feedback.outcome, "value", str(feedback.outcome)).strip().lower()

    if finding_class in {"sensitive_exposure", "secret_exposure"} and "replay_with_token" in hints:
        return "sensitive_exposure_adaptive_followup"
    if finding_class == "graphql_introspection" and "schema_driven_field_probe" in hints:
        return "graphql_schema_driven_probe"
    if outcome == TaskOutcome.blocked.value and "bfla_follow_up" in hints:
        return "bfla_role_switch"
    if outcome == TaskOutcome.needs_followup.value:
        normalized = finding_class or "generic"
        return f"{normalized}_followup"
    return None


def _followup_task_fingerprint(
    scan_id: str,
    endpoint_id: str,
    attack_class: str,
    hypothesis_fragment: str,
) -> str:
    joined = "|".join(
        (
            str(scan_id).strip(),
            str(endpoint_id).strip(),
            str(attack_class).strip().lower(),
            str(hypothesis_fragment).strip(),
        )
    )
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


async def _check_replan_budget(scan_id: str, redis_client: Any) -> bool:
    rounds_key = f"replan:rounds:{scan_id}"
    rounds = await redis_client.incr(rounds_key)
    if rounds == 1:
        await redis_client.expire(rounds_key, 86400)
    return rounds <= MAX_REPLAN_ROUNDS


async def replan_attack(scan_id: str, feedback_payload_dict: dict[str, Any]) -> None:
    from redis.asyncio import Redis as AsyncRedis
    from sqlalchemy.orm import selectinload
    from storage.db.session import AsyncSessionLocal

    feedback = _feedback_payload_from_dict(feedback_payload_dict)
    playbook_id = _select_followup_playbook(feedback)
    if not playbook_id:
        logger.info("replan_no_matching_playbook", scan_id=scan_id, finding_class=feedback.finding_class)
        return

    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        logger.warning("replan_redis_url_missing", scan_id=scan_id)
        return

    redis_client = AsyncRedis.from_url(redis_url, decode_responses=True)
    try:
        budget_ok = await _check_replan_budget(scan_id, redis_client)
        if not budget_ok:
            logger.info("replan_budget_exhausted", scan_id=scan_id)
            return

        scan_uuid = UUID(scan_id)
        task_uuid = UUID(feedback.task_id)
        async with AsyncSessionLocal() as session:
            source_task_result = await session.execute(
                select(AttackTask)
                .where(AttackTask.id == task_uuid, AttackTask.scan_id == scan_uuid)
                .options(selectinload(AttackTask.endpoint))
            )
            source_task = source_task_result.scalar_one_or_none()
            if source_task is None or source_task.endpoint is None:
                logger.warning("replan_source_task_or_endpoint_missing", scan_id=scan_id, task_id=feedback.task_id)
                return

            scan_record = await _load_scan_with_asset_map(session=session, scan_id=scan_uuid)
            if scan_record is None or scan_record.asset_map is None:
                logger.warning("replan_scan_or_asset_map_missing", scan_id=scan_id)
                return

            from storage.db.models import ScanStatus as _ScanStatus
            if scan_record.status not in {_ScanStatus.running, _ScanStatus.created}:
                logger.info("replan_scan_not_active", scan_id=scan_id, status=str(scan_record.status))
                return

            planner = AttackPlanner()
            selected_playbook = next((playbook for playbook in planner.playbooks if playbook.id == playbook_id), None)
            if selected_playbook is None:
                logger.warning("replan_playbook_not_found", scan_id=scan_id, playbook_id=playbook_id)
                return

            target_url = _resolve_target_url(asset_map={}, scan=scan_record)
            context = ScanContext(scan_id=scan_uuid, target_url=target_url, asset_map=scan_record.asset_map)
            candidate_tasks = planner._tasks_from_playbook(
                playbook=selected_playbook,
                endpoint=source_task.endpoint,
                context=context,
                selection_reason="adaptive_replan",
            )

            dedup_key = f"replan:dedup:{scan_id}"
            created_count = 0
            for task in candidate_tasks[:MAX_REPLAN_TASKS_PER_JOB]:
                hypothesis_payload = planner._parse_hypothesis_config(task.hypothesis)
                if feedback.parent_evidence_ref is not None:
                    hypothesis_payload["parent_evidence_ref"] = feedback.parent_evidence_ref
                    task.hypothesis = json.dumps(hypothesis_payload, sort_keys=True)
                task.parent_evidence_ref = feedback.parent_evidence_ref

                hypothesis_fragment = str(hypothesis_payload.get("step_id") or hypothesis_payload.get("probe_type") or task.hypothesis)
                fingerprint = _followup_task_fingerprint(
                    scan_id=scan_id,
                    endpoint_id=str(task.endpoint_id),
                    attack_class=task.attack_class,
                    hypothesis_fragment=hypothesis_fragment,
                )
                already_exists = await redis_client.sismember(dedup_key, fingerprint)
                if already_exists:
                    continue
                await redis_client.sadd(dedup_key, fingerprint)
                await redis_client.expire(dedup_key, 86400)
                session.add(task)
                created_count += 1

            if created_count > 0:
                await session.commit()
            logger.info(
                "replan_attack_tasks_created",
                scan_id=scan_id,
                playbook_id=playbook_id,
                created_count=created_count,
            )
    except Exception as exc:
        logger.exception("replan_attack_failed", scan_id=scan_id)
    finally:
        await redis_client.aclose()


def rq_enqueue_replan(scan_id: str, feedback: FeedbackPayload | dict[str, Any]) -> None:
    from redis import Redis
    from rq import Queue as RQueue

    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        logger.warning("rq_enqueue_replan_redis_url_missing", scan_id=scan_id)
        return

    feedback_payload_dict: dict[str, Any]
    if isinstance(feedback, FeedbackPayload):
        feedback_payload_dict = {
            "outcome": getattr(feedback.outcome, "value", str(feedback.outcome)),
            "scan_id": feedback.scan_id,
            "task_id": feedback.task_id,
            "endpoint": feedback.endpoint,
            "finding_class": feedback.finding_class,
            "confidence": feedback.confidence,
            "follow_up_hints": feedback.follow_up_hints,
            "parent_evidence_ref": feedback.parent_evidence_ref,
            "metadata": feedback.metadata,
        }
    else:
        feedback_payload_dict = feedback

    queue_name = os.getenv("RQ_ATTACK_QUEUE", "attack_planning")
    queue = RQueue(name=queue_name, connection=Redis.from_url(redis_url))
    queue.enqueue("execution_plane.planner.planner.replan_attack", scan_id, feedback_payload_dict)
    logger.info("rq_replan_enqueued", scan_id=scan_id, queue=queue_name)


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
        scan_budget = _scan_budget_from_scan(scan_record)
        tasks = planner.plan(scan_context, scan_budget=scan_budget)
        endpoint_by_id = {endpoint.id: endpoint for endpoint in endpoints}
        for task in tasks:
            endpoint = endpoint_by_id.get(task.endpoint_id)
            if endpoint is not None:
                task.endpoint = endpoint
        policy = _policy_from_scan(scan_record)
        tasks, skipped_tasks = filter_tasks_by_policy(tasks, policy)
        skipped_records: list[dict[str, str]] = []
        for skipped_task, policy_field in skipped_tasks:
            skipped_task.status = AttackTaskStatus.failed
            reason = f"policy:{policy_field}"
            skipped_records.append(
                {
                    "task_id": str(skipped_task.id),
                    "reason": reason,
                    "attack_class": str(skipped_task.attack_class),
                }
            )
            session.add(
                AuditEvent(
                    event_type=AuditEventType.TASK_SKIPPED,
                    scan_id=scan_uuid,
                    actor="planner",
                    details=redact_for_audit({"task_id": str(skipped_task.id), "reason": reason}),
                )
            )
        tasks.extend(skipped_task for skipped_task, _ in skipped_tasks)
        session.add_all(tasks)
        await session.commit()
        try:
            import os
            from redis import Redis
            from rq import Queue as RQueue
            _redis_url = os.getenv("REDIS_URL")
            if _redis_url:
                _conn = Redis.from_url(_redis_url)
                _store_skipped_task_records(_conn, scan_id, skipped_records)
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


def _policy_from_scan(scan: Scan) -> ScanPolicy:
    config = scan.target.config if scan.target is not None and isinstance(scan.target.config, dict) else {}
    raw_policy = config.get("policy")
    if isinstance(raw_policy, ScanPolicy):
        return raw_policy
    if isinstance(raw_policy, dict):
        return ScanPolicy(**raw_policy)
    allowed_domains = config.get("allowed_domains")
    if isinstance(allowed_domains, list):
        return ScanPolicy(allowed_domains=[str(domain) for domain in allowed_domains if domain])
    return ScanPolicy()


def _scan_budget_from_scan(scan: Scan) -> ScanBudget | None:
    config = scan.target.config if scan.target is not None and isinstance(scan.target.config, dict) else {}
    raw_budget = config.get("scan_budget")
    if not isinstance(raw_budget, dict):
        return None
    max_requests = raw_budget.get("max_requests")
    max_runtime_seconds = raw_budget.get("max_runtime_seconds")
    if not isinstance(max_requests, int) or isinstance(max_requests, bool):
        return None
    if not isinstance(max_runtime_seconds, int) or isinstance(max_runtime_seconds, bool):
        return None
    raw_caps = raw_budget.get("per_class_cap", {})
    per_class_cap: dict[str, int] = {}
    if isinstance(raw_caps, dict):
        for key, value in raw_caps.items():
            if isinstance(key, str) and isinstance(value, int) and not isinstance(value, bool):
                per_class_cap[key] = value
    raw_priority = raw_budget.get("priority_classes", [])
    priority_classes = [item for item in raw_priority if isinstance(item, str)]
    return ScanBudget(
        max_requests=max_requests,
        max_runtime_seconds=max_runtime_seconds,
        per_class_cap=per_class_cap,
        priority_classes=priority_classes,
    )


def _store_skipped_task_records(redis_client: Any, scan_id: str, skipped_records: list[dict]) -> None:
    if not skipped_records:
        return
    key = f"skipped_tasks:{scan_id}"
    for record in skipped_records:
        redis_client.rpush(key, json.dumps(record, sort_keys=True))
