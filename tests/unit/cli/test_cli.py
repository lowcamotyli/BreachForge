from __future__ import annotations

from unittest.mock import Mock, patch

from click.testing import CliRunner

from cli.gate_runner import GateRunner
from cli.main import breachforge


def test_scan_create_success() -> None:
    runner = CliRunner()

    mock_response = Mock()
    mock_response.json.return_value = {"id": "abc"}
    mock_response.raise_for_status.return_value = None

    mock_client = Mock()
    mock_client.__enter__ = Mock(return_value=mock_client)
    mock_client.__exit__ = Mock(return_value=False)
    mock_client.post.return_value = mock_response

    with patch("cli.main.httpx.Client", return_value=mock_client):
        result = runner.invoke(breachforge, ["scan", "create", "--target", "https://example.com"])

    assert result.exit_code == 0
    assert "abc" in result.output


def test_scan_wait_polls_until_done() -> None:
    runner = CliRunner()

    pending_response = Mock()
    pending_response.json.return_value = {"status": "pending"}
    pending_response.raise_for_status.return_value = None

    done_response = Mock()
    done_response.json.return_value = {"status": "completed"}
    done_response.raise_for_status.return_value = None

    mock_client = Mock()
    mock_client.__enter__ = Mock(return_value=mock_client)
    mock_client.__exit__ = Mock(return_value=False)
    mock_client.get.side_effect = [pending_response, done_response]

    with (
        patch("cli.main.httpx.Client", return_value=mock_client),
        patch("cli.main.time.sleep", return_value=None),
    ):
        result = runner.invoke(
            breachforge,
            ["scan", "wait", "--scan-id", "scan-1", "--timeout", "10", "--poll-interval", "0"],
        )

    assert result.exit_code == 0
    assert "completed" in result.output
    assert mock_client.get.call_count == 2


def test_gate_runner_pass() -> None:
    gate = GateRunner(max_new_critical=0, max_new_high=5, no_auth_failure=True)
    passed, _reason = gate.evaluate(
        {"new_critical": 0, "new_high": 2, "auth_failures": 0}
    )
    assert passed is True


def test_gate_runner_fail_critical() -> None:
    gate = GateRunner(max_new_critical=0, max_new_high=5, no_auth_failure=True)
    passed, _reason = gate.evaluate(
        {"new_critical": 1, "new_high": 0, "auth_failures": 0}
    )
    assert passed is False
