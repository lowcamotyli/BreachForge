from __future__ import annotations

from control_plane.secret_correlation import SecretExposureCorrelator, SeverityFactor


def test_critical_upgrade() -> None:
    result = SecretExposureCorrelator().correlate(
        {
            "active_replay": True,
            "unauthenticated_exposure": True,
        }
    )

    assert result.severity_upgrade == "Critical"
    assert result.noise_guard_triggered is False
    assert result.severity_factors == [
        SeverityFactor(
            source="active_replay",
            confidence=0.95,
            description="Secret replay succeeded against the exposed target.",
        ),
        SeverityFactor(
            source="unauthenticated_exposure",
            confidence=0.95,
            description="The secret exposure is reachable without authentication.",
        ),
    ]


def test_high_upgrade_blast_radius() -> None:
    result = SecretExposureCorrelator().correlate(
        {
            "active_replay": True,
            "blast_radius_score": 0.8,
        }
    )

    assert result.severity_upgrade == "High"
    assert result.noise_guard_triggered is False
    assert result.severity_factors == [
        SeverityFactor(
            source="active_replay",
            confidence=0.85,
            description="Secret replay succeeded against the exposed target.",
        ),
        SeverityFactor(
            source="blast_radius",
            confidence=0.85,
            description="Blast radius evidence shows broad downstream impact.",
        ),
    ]


def test_no_upgrade_cors_alone() -> None:
    result = SecretExposureCorrelator().correlate({"cors_permissive": True})

    assert result.severity_upgrade is None
    assert result.severity_factors == []
    assert result.noise_guard_triggered is True


def test_no_upgrade_cache_alone() -> None:
    result = SecretExposureCorrelator().correlate({"cache_permissive": True})

    assert result.severity_upgrade is None
    assert result.severity_factors == []
    assert result.noise_guard_triggered is True


def test_noise_guard_single_weak_signal() -> None:
    result = SecretExposureCorrelator().correlate({"blast_radius_score": 0.4})

    assert result.severity_upgrade is None
    assert result.severity_factors == [
        SeverityFactor(
            source="blast_radius_score",
            confidence=0.4,
            description="Blast-radius signal was present but below upgrade threshold.",
        )
    ]
    assert result.noise_guard_triggered is True


def test_empty_signals() -> None:
    result = SecretExposureCorrelator().correlate(
        {
            "active_replay": False,
            "blast_radius_score": 0.0,
            "cors_permissive": False,
            "cache_permissive": False,
            "unauthenticated_exposure": False,
        }
    )

    assert result.severity_upgrade is None
    assert result.severity_factors == []
    assert result.noise_guard_triggered is False


def test_deterministic() -> None:
    correlator = SecretExposureCorrelator()
    signals = {
        "active_replay": True,
        "blast_radius_score": 0.9,
        "cors_permissive": True,
    }

    assert correlator.correlate(signals) == correlator.correlate(signals)


def test_severity_factors_have_required_fields() -> None:
    result = SecretExposureCorrelator().correlate(
        {
            "active_replay": True,
            "blast_radius_score": 0.8,
        }
    )

    for factor in result.severity_factors:
        assert isinstance(factor.source, str)
        assert isinstance(factor.confidence, float)
        assert isinstance(factor.description, str)
        assert factor.source
        assert factor.description
