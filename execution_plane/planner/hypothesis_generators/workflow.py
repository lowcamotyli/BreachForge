from __future__ import annotations

from typing import Any

from execution_plane.planner.hypotheses import AttackHypothesis, AttackSignal, build_endpoint_signals, extract_flow_hints_from_endpoint

_STATE_MUTATION_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def generate_workflow_hypotheses(asset_map: Any) -> list[AttackHypothesis]:
    endpoints = getattr(asset_map, "endpoints", [])
    if not isinstance(endpoints, list):
        return []

    hypotheses: list[AttackHypothesis] = []
    for endpoint in endpoints:
        method = str(getattr(endpoint, "method", "GET")).strip().upper() or "GET"
        hints = extract_flow_hints_from_endpoint(endpoint)
        if not hints:
            continue

        if method not in _STATE_MUTATION_METHODS and not any(hint in {"approve", "admin"} for hint in hints):
            continue

        url_pattern = str(getattr(endpoint, "url_pattern", "")).strip().lower()
        if not url_pattern:
            continue

        signals = list(build_endpoint_signals(endpoint))
        for hint in hints:
            signals.append(
                AttackSignal(
                    kind="state_delta",
                    key="workflow_hint",
                    value=hint,
                    endpoint=url_pattern,
                    method=method,
                    tags=("workflow",),
                )
            )

        identities = ["standard_user"]
        if "admin" in hints or "approve" in hints or "status" in hints:
            identities.append("elevated_user")

        candidate_playbooks = ["workflow_abuse"]
        if "admin" in hints or "approve" in hints or "status" in hints or "status" in url_pattern:
            candidate_playbooks.append("privilege_drift")

        hypotheses.append(
            AttackHypothesis(
                type="workflow_privilege",
                target=f"{method} {url_pattern}",
                rationale=(
                    "Observed flow/action hints indicate a state transition or privileged control path; "
                    "step ordering and role enforcement should be challenged."
                ),
                required_identities=tuple(identities),
                candidate_playbooks=tuple(candidate_playbooks),
                confidence=0.62,
                signals=tuple(signals),
            )
        )

    return sorted(hypotheses, key=lambda hypothesis: (hypothesis.target, hypothesis.type))
