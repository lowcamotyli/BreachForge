from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from execution_plane.planner.hypotheses import AttackHypothesis, AttackSignal, build_endpoint_signals
from execution_plane.planner.secret_blast_radius import BlastRadiusSelector

_SECRET_SOURCE_HINTS: tuple[str, ...] = (
    "auth",
    "token",
    "session",
    "secret",
    "key",
    "credential",
    "password",
)


def generate_secret_impact_hypotheses(asset_map: Any) -> list[AttackHypothesis]:
    endpoints = getattr(asset_map, "endpoints", [])
    if not isinstance(endpoints, list):
        return []

    source_endpoints = _candidate_secret_sources(endpoints)
    hypotheses: list[AttackHypothesis] = []

    for source in source_endpoints:
        source_pattern = str(getattr(source, "url_pattern", "")).strip().lower()
        selector = BlastRadiusSelector(_to_blast_radius_asset_map(asset_map), source_endpoint_pattern=source_pattern)
        blast_radius_candidates = selector.select()
        if not blast_radius_candidates:
            continue

        signals = list(build_endpoint_signals(source))
        for candidate in blast_radius_candidates:
            signals.append(
                AttackSignal(
                    kind="response_delta",
                    key="blast_radius_endpoint",
                    value=f"{candidate['method']} {candidate['url_pattern']}",
                    endpoint=source_pattern,
                    method=str(getattr(source, "method", "GET")).upper(),
                    tags=("blast_radius", "secret_impact"),
                )
            )

        hypotheses.append(
            AttackHypothesis(
                type="secret_impact",
                target=f"source={str(getattr(source, 'method', 'GET')).upper()} {source_pattern}",
                rationale=(
                    "Potential credential/session-bearing endpoint can enable post-compromise reach; "
                    "blast-radius verification should probe read-only high-value resources."
                ),
                required_identities=("compromised_identity",),
                candidate_playbooks=("secret_to_impact",),
                confidence=0.58,
                signals=tuple(signals),
            )
        )

    return sorted(hypotheses, key=lambda hypothesis: (hypothesis.target, hypothesis.type))


def _candidate_secret_sources(endpoints: list[Any]) -> list[Any]:
    ranked: list[tuple[tuple[int, str, str], Any]] = []
    for endpoint in endpoints:
        url_pattern = str(getattr(endpoint, "url_pattern", "")).strip().lower()
        method = str(getattr(endpoint, "method", "GET")).strip().upper() or "GET"
        if not url_pattern:
            continue

        hint_score = sum(1 for hint in _SECRET_SOURCE_HINTS if hint in url_pattern)
        if hint_score == 0:
            continue

        ranked.append(((-hint_score, method, url_pattern), endpoint))

    ranked.sort(key=lambda item: item[0])
    deduped: list[Any] = []
    seen: set[str] = set()
    for _, endpoint in ranked:
        signature = f"{str(getattr(endpoint, 'method', 'GET')).upper()}:{str(getattr(endpoint, 'url_pattern', '')).lower()}"
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(endpoint)
    return deduped


@dataclass(slots=True)
class _BlastRadiusEndpoint:
    url_pattern: str
    method: str
    in_scope: bool
    auth_required: bool


@dataclass(slots=True)
class _BlastRadiusAssetMap:
    endpoints: list[_BlastRadiusEndpoint]


def _to_blast_radius_asset_map(asset_map: Any) -> _BlastRadiusAssetMap:
    raw_endpoints = getattr(asset_map, "endpoints", [])
    adapted: list[_BlastRadiusEndpoint] = []
    if not isinstance(raw_endpoints, list):
        return _BlastRadiusAssetMap(endpoints=adapted)

    for endpoint in raw_endpoints:
        adapted.append(
            _BlastRadiusEndpoint(
                url_pattern=str(getattr(endpoint, "url_pattern", "")),
                method=str(getattr(endpoint, "method", "GET")).upper(),
                in_scope=bool(getattr(endpoint, "in_scope", True)),
                auth_required=bool(getattr(endpoint, "auth_required", False)),
            )
        )
    return _BlastRadiusAssetMap(endpoints=adapted)
