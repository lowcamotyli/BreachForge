from __future__ import annotations

from pathlib import Path

from docs.reporting.scorecard_renderer import ScorecardRenderer, version_header


def _sample_metrics() -> dict[str, object]:
    return {
        "corpus_version": "v1.0.0",
        "engine_config_version": "abc1234",
        "schema_version": "1.0.0",
        "coverage_by_attack_class": {
            "bola": {
                "tested": 4,
                "tp": 3,
                "fp": 1,
                "fn": 0,
                "covered_pct": 0.75,
            }
        },
        "false_positive_false_negative_summary": {
            "bola": {
                "fp_count": 1,
                "fn_count": 0,
                "notes": "one noisy endpoint",
            }
        },
        "proof_depth": {
            "bola": {
                "proof_type": "differential_http",
                "avg_confidence": 0.91,
                "min_confidence": 0.82,
            }
        },
        "auth_discovery_health": {
            "auth_sessions_tested": 2,
            "discovery_coverage_pct": 0.88,
            "blind_spots_count": 1,
            "auth_failures": 0,
        },
        "unsupported_classes": [
            {
                "class": "xxe",
                "reason": "not in public corpus v1",
            }
        ],
    }


def test_scorecard_renderer_creates_file(tmp_path: Path) -> None:
    output_path = tmp_path / "scorecard.md"

    ScorecardRenderer().render(_sample_metrics(), output_path)

    assert output_path.exists()


def test_scorecard_renderer_markdown_has_sections(tmp_path: Path) -> None:
    output_path = tmp_path / "scorecard.md"

    ScorecardRenderer().render(_sample_metrics(), output_path)
    rendered = output_path.read_text(encoding="utf-8").lower()

    assert "coverage by attack class" in rendered
    assert "proof depth" in rendered
    assert "auth / discovery health" in rendered


def test_version_header_contains_versions() -> None:
    header = version_header("v1.0.0", "abc1234", "1.0.0")

    assert "v1.0.0" in header
    assert "abc1234" in header
    assert "1.0.0" in header
