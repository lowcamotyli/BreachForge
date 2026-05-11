from __future__ import annotations

from dataclasses import dataclass

_SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_SEVERITY: dict[int, str] = {v: k for k, v in _SEVERITY_RANK.items()}
_BOLA_CLASSES = frozenset({"bola", "tenant_isolation"})
_AUTHZ_CLASSES = frozenset({"auth_bypass", "privilege_escalation"})
_EXPOSURE_CLASSES = frozenset({"sensitive_exposure", "secret_exposure"})

def _ensure_unit_interval(name: str, value: float) -> float:
    v = float(value)
    if not 0.0 <= v <= 1.0:
        raise ValueError(f"{name} must be within [0, 1], got {v}")
    return v

@dataclass(slots=True)
class ChainConfidenceResult:
    chain_confidence: float
    weakest_step: str
    has_differential_support: bool
    has_reproducible_steps: bool

def compute_chain_confidence(step_confidences: list[tuple[str, float]], has_differential: bool, has_reproducible: bool) -> ChainConfidenceResult:
    if not step_confidences:
        return ChainConfidenceResult(chain_confidence=0.0, weakest_step="", has_differential_support=has_differential, has_reproducible_steps=has_reproducible)
    weakest_phase, min_conf = min(step_confidences, key=lambda t: t[1])
    chain_conf = min(min_conf * 1.05, 1.0) if has_differential and has_reproducible else min_conf
    return ChainConfidenceResult(chain_confidence=round(chain_conf, 4), weakest_step=weakest_phase, has_differential_support=has_differential, has_reproducible_steps=has_reproducible)

@dataclass(slots=True)
class SeverityAdjustment:
    original: str
    adjusted: str
    explanation: str

def adjust_chain_severity(base_severity: str, chain_confidence: float, has_impact_evidence: bool, step_count: int) -> SeverityAdjustment:
    original = base_severity.lower()
    rank = _SEVERITY_RANK.get(original, 2)
    parts: list[str] = []
    if original == "high" and has_impact_evidence and step_count >= 3 and chain_confidence >= 0.85:
        rank = _SEVERITY_RANK["critical"]
        parts.append("upgraded to critical: multi-step chain with proven impact evidence")
    elif original == "critical" and not has_impact_evidence:
        rank = _SEVERITY_RANK["high"]
        parts.append("downgraded from critical: no confirmed impact evidence")
    if chain_confidence < 0.70:
        rank = max(rank - 1, _SEVERITY_RANK["info"])
        parts.append(f"downgraded one level: chain confidence {chain_confidence:.2f} < 0.70")
    adjusted = _RANK_SEVERITY[rank]
    if not parts:
        parts.append(f"severity unchanged at {adjusted}")
    return SeverityAdjustment(original=original, adjusted=adjusted, explanation="; ".join(parts))

def compute_chain_score(impact: float, reachability: float, privilege: float, repeatability: float, blast_radius: float, safety_confidence: float) -> dict[str, float]:
    factors = {
        "impact": _ensure_unit_interval("impact", impact),
        "reachability": _ensure_unit_interval("reachability", reachability),
        "privilege": _ensure_unit_interval("privilege", privilege),
        "repeatability": _ensure_unit_interval("repeatability", repeatability),
        "blast_radius": _ensure_unit_interval("blast_radius", blast_radius),
        "safety_confidence": _ensure_unit_interval("safety_confidence", safety_confidence),
    }
    total = 1.0
    for v in factors.values():
        total *= v
    factors["total"] = round(total, 6)
    return factors

def build_remediation(attack_class: str, root_cause_endpoint: str, step_count: int, identities: list[str]) -> str:
    identity_note = f" Affected identities: {len(identities)}." if len(identities) > 1 else ""
    chain_note = f" This is a {step_count}-step attack chain." if step_count > 1 else ""
    if attack_class in _BOLA_CLASSES:
        return f"Fix object-level authorization at {root_cause_endpoint}: enforce ownership checks on every resource access, not just at route level.{chain_note}{identity_note}"
    if attack_class in _AUTHZ_CLASSES:
        return f"Harden authentication and role validation at {root_cause_endpoint}: verify session server-side and enforce least-privilege role boundaries.{chain_note}{identity_note}"
    if attack_class in _EXPOSURE_CLASSES:
        return f"Filter sensitive data from responses at {root_cause_endpoint}: rotate any exposed credentials and audit all endpoints that return secret material.{chain_note}{identity_note}"
    return f"Fix the root cause at {root_cause_endpoint} first, then validate that downstream steps no longer succeed.{chain_note}{identity_note}"
