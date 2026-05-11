from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from control_plane.auth_manager import IdentityMatrix, IdentityProfile


@dataclass(slots=True, kw_only=True)
class DifferentialProbePlan:
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    baseline_identity: str
    challenger_identities: list[str]
    target_url: str
    method: str = "GET"
    payload: dict[str, Any] | None = None
    headers: dict[str, str] | None = None


def build_differential_plans(
    matrix: IdentityMatrix,
    target_url: str,
    method: str = "GET",
    baseline: str | None = None,
    payload: dict[str, Any] | None = None,
) -> list[DifferentialProbePlan]:
    identity_names = _identity_names(matrix)
    if len(identity_names) < 2:
        raise ValueError(f"IdentityMatrix must have at least 2 identities, got {len(identity_names)}")

    chosen_baseline = baseline if baseline is not None else identity_names[0]
    challenger_identities = [identity_name for identity_name in identity_names if identity_name != chosen_baseline]
    if not challenger_identities:
        raise ValueError("No challenger identities after excluding baseline")

    return [
        DifferentialProbePlan(
            baseline_identity=chosen_baseline,
            challenger_identities=challenger_identities,
            target_url=target_url,
            method=method,
            payload=payload,
        )
    ]


def _identity_names(matrix: IdentityMatrix) -> list[str]:
    identities_by_name: dict[str, IdentityProfile] = matrix
    return list(identities_by_name.keys())
