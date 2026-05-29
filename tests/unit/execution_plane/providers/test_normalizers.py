from __future__ import annotations

from execution_plane.providers.base import ToolResult
from execution_plane.providers.normalizers import ToolOutputNormalizer


def _make_result(
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    json_output: dict[str, object] | list[object] | None = None,
    provider_id: str = "dummy-provider",
) -> ToolResult:
    return ToolResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        json_output=json_output,
        elapsed_seconds=0.1,
        provider_id=provider_id,
    )


def test_to_raw_probe_returns_provider_id() -> None:
    result = _make_result(stdout="out", provider_id="zap")

    probe = ToolOutputNormalizer.to_raw_probe(result, scan_id="scan-1", target_url="https://t")

    assert probe["provider_id"] == "zap"


def test_to_raw_probe_truncates_response_body_at_1mb() -> None:
    result = _make_result(stdout="a" * 1_000_100)

    probe = ToolOutputNormalizer.to_raw_probe(result, scan_id="scan-1", target_url="https://t")

    assert len(probe["response_body"]) == 1_000_000


def test_to_discovery_signals_returns_empty_for_non_json_output() -> None:
    result = _make_result(stdout="plain text", json_output=None)

    signals = ToolOutputNormalizer.to_discovery_signals(result)

    assert signals == []


def test_to_discovery_signals_parses_findings_key_list() -> None:
    result = _make_result(json_output={"findings": [{"id": 1}, {"id": 2}]})

    signals = ToolOutputNormalizer.to_discovery_signals(result)

    assert len(signals) == 2
    assert signals[0]["signal_type"] == "provider_discovery"
    assert signals[0]["provider_id"] == "dummy-provider"
    assert signals[0]["raw"] == {"id": 1}
    assert "finding" not in signals[0]


def test_to_discovery_signals_handles_flat_list() -> None:
    result = _make_result(json_output=[{"sev": "high"}, {"sev": "low"}])

    signals = ToolOutputNormalizer.to_discovery_signals(result)

    assert len(signals) == 2
    assert signals[1]["raw"] == {"sev": "low"}


def test_validate_output_true_for_exit_code_zero_with_stdout() -> None:
    result = _make_result(stdout="ok", exit_code=0)

    assert ToolOutputNormalizer.validate_output(result) is True


def test_validate_output_false_for_exit_code_non_zero() -> None:
    result = _make_result(stdout="ok", exit_code=1)

    assert ToolOutputNormalizer.validate_output(result) is False
