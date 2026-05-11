from __future__ import annotations

from typing import Any

from execution_plane.planner.hypotheses import AttackHypothesis, AttackSignal, build_endpoint_signals, extract_high_risk_parameters

_BOLA_ID_HINTS: frozenset[str] = frozenset({"id", "user_id", "org_id", "tenant_id"})


def generate_bola_hypotheses(asset_map: Any) -> list[AttackHypothesis]:
    endpoints = getattr(asset_map, "endpoints", [])
    if not isinstance(endpoints, list):
        return []

    hypotheses: list[AttackHypothesis] = []
    for endpoint in endpoints:
        method = str(getattr(endpoint, "method", "GET")).strip().upper() or "GET"
        if method not in {"GET", "PUT", "PATCH", "DELETE"}:
            continue

        high_risk_parameters = extract_high_risk_parameters(endpoint)
        id_parameters = tuple(param for param in high_risk_parameters if param in _BOLA_ID_HINTS)
        if not id_parameters:
            continue

        url_pattern = str(getattr(endpoint, "url_pattern", "")).strip().lower()
        if not url_pattern:
            continue

        signals = list(build_endpoint_signals(endpoint))
        for parameter in id_parameters:
            signals.append(
                AttackSignal(
                    kind="identity",
                    key="cross_identity_target",
                    value=parameter,
                    endpoint=url_pattern,
                    method=method,
                    tags=("bola", "idor"),
                )
            )

        target = f"{method} {url_pattern}::{','.join(id_parameters)}"
        hypotheses.append(
            AttackHypothesis(
                type="bola_idor",
                target=target,
                rationale=(
                    "Resource ownership identifiers are present on an authenticated endpoint; "
                    "cross-identity substitution should be validated for unauthorized access."
                ),
                required_identities=("attacker_identity", "foreign_identity"),
                candidate_playbooks=("bola_idor",),
                confidence=0.7,
                signals=tuple(signals),
            )
        )

    return sorted(hypotheses, key=lambda hypothesis: (hypothesis.target, hypothesis.type))
