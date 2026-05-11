from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SeverityFactor:
    source: str
    confidence: float
    description: str


@dataclass(slots=True)
class CorrelationResult:
    severity_upgrade: str | None
    severity_factors: list[SeverityFactor] = field(default_factory=list)
    noise_guard_triggered: bool = False


class SecretExposureCorrelator:
    def correlate(self, signals: dict[str, Any]) -> CorrelationResult:
        active_replay = bool(signals.get("active_replay", False))
        blast_radius_score = self._blast_radius_score(signals.get("blast_radius_score", 0.0))
        cors_permissive = bool(signals.get("cors_permissive", False))
        cache_permissive = bool(signals.get("cache_permissive", False))
        unauthenticated_exposure = bool(signals.get("unauthenticated_exposure", False))

        if active_replay and unauthenticated_exposure:
            return CorrelationResult(
                severity_upgrade="Critical",
                severity_factors=[
                    SeverityFactor(
                        source="active_replay",
                        confidence=0.95,
                        description="Secret replay succeeded against the exposed target.",
                    ),
                    SeverityFactor(
                        source="unauthenticated_exposure",
                        confidence=0.95,
                        description="The secret exposure is reachable without authentication.",
                    )
                ],
            )

        if active_replay and blast_radius_score >= 0.7:
            return CorrelationResult(
                severity_upgrade="High",
                severity_factors=[
                    SeverityFactor(
                        source="active_replay",
                        confidence=0.85,
                        description="Secret replay succeeded against the exposed target.",
                    ),
                    SeverityFactor(
                        source="blast_radius",
                        confidence=0.85,
                        description="Blast radius evidence shows broad downstream impact.",
                    )
                ],
            )

        if (cors_permissive or cache_permissive) and not active_replay and not unauthenticated_exposure:
            return CorrelationResult(severity_upgrade=None, noise_guard_triggered=True)

        present_factors = self._present_factors(
            active_replay=active_replay,
            blast_radius_score=blast_radius_score,
            cors_permissive=cors_permissive,
            cache_permissive=cache_permissive,
            unauthenticated_exposure=unauthenticated_exposure,
        )
        if len(present_factors) == 1 and present_factors[0].confidence < 0.5:
            return CorrelationResult(
                severity_upgrade=None,
                severity_factors=present_factors,
                noise_guard_triggered=True,
            )

        return CorrelationResult(severity_upgrade=None, noise_guard_triggered=False)

    def _blast_radius_score(self, value: Any) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            return 0.0
        return min(max(score, 0.0), 1.0)

    def _present_factors(
        self,
        active_replay: bool,
        blast_radius_score: float,
        cors_permissive: bool,
        cache_permissive: bool,
        unauthenticated_exposure: bool,
    ) -> list[SeverityFactor]:
        factors: list[SeverityFactor] = []
        if active_replay:
            factors.append(
                SeverityFactor(
                    source="active_replay",
                    confidence=0.8,
                    description="Secret replay was observed without a qualifying exposure or blast-radius signal.",
                )
            )
        if blast_radius_score > 0.0:
            factors.append(
                SeverityFactor(
                    source="blast_radius_score",
                    confidence=blast_radius_score,
                    description="Blast-radius signal was present but below upgrade threshold.",
                )
            )
        if cors_permissive:
            factors.append(
                SeverityFactor(
                    source="cors_permissive",
                    confidence=0.35,
                    description="Permissive CORS was observed without active exploitation evidence.",
                )
            )
        if cache_permissive:
            factors.append(
                SeverityFactor(
                    source="cache_permissive",
                    confidence=0.35,
                    description="Permissive cache behavior was observed without active exploitation evidence.",
                )
            )
        if unauthenticated_exposure:
            factors.append(
                SeverityFactor(
                    source="unauthenticated_exposure",
                    confidence=0.45,
                    description="Unauthenticated exposure was observed without active replay evidence.",
                )
            )
        return factors
