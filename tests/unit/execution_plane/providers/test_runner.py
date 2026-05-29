from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from execution_plane.providers.runner import SandboxedProviderRunner


def test_shell_false_enforced() -> None:
    runner = SandboxedProviderRunner()
    with patch("execution_plane.providers.runner.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["python", "-V"],
            returncode=0,
            stdout="ok",
            stderr="",
        )

        runner.run_provider(["python", "-V"], timeout=3, max_memory_mb=128)

    assert mock_run.called
    assert mock_run.call_args.kwargs["shell"] is False


def test_timeout_returns_exit_code_minus_one() -> None:
    runner = SandboxedProviderRunner()
    with patch("execution_plane.providers.runner.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["sleep", "10"], timeout=1)

        result = runner.run_provider(["sleep", "10"], timeout=1, max_memory_mb=128)

    assert result["exit_code"] == -1
    assert isinstance(result["elapsed_seconds"], float)


def test_command_passed_as_list() -> None:
    runner = SandboxedProviderRunner()
    with patch("execution_plane.providers.runner.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["echo", "ok"],
            returncode=0,
            stdout="ok",
            stderr="",
        )

        runner.run_provider(["echo", "ok"], timeout=2, max_memory_mb=128)

    called_args = mock_run.call_args.args[0]
    assert isinstance(called_args, list)
    assert called_args == ["echo", "ok"]


def test_rejects_credentials_in_args() -> None:
    runner = SandboxedProviderRunner()

    with pytest.raises(ValueError, match="credentials"):
        runner.run_provider(["tool", "password=secret"], timeout=2, max_memory_mb=128)

    with pytest.raises(ValueError, match="credentials"):
        runner.run_provider(["tool", "token=abc"], timeout=2, max_memory_mb=128)


def test_argument_injection_payload_is_passed_as_literal_arg() -> None:
    runner = SandboxedProviderRunner()
    injection_payload = "https://example.com;cat /etc/passwd"
    with patch("execution_plane.providers.runner.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["tool", injection_payload],
            returncode=0,
            stdout="ok",
            stderr="",
        )

        runner.run_provider(["tool", injection_payload], timeout=2, max_memory_mb=128)

    called_args = mock_run.call_args.args[0]
    assert called_args == ["tool", injection_payload]
    assert mock_run.call_args.kwargs["shell"] is False
