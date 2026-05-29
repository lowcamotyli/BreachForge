from __future__ import annotations

from cli.local_dev import LocalDevScanner, redact_artifact


def test_redact_artifact_authorization() -> None:
    data = {"Authorization": "Bearer secret-token", "target_url": "https://example.com"}

    redacted = redact_artifact(data)

    assert redacted["Authorization"] == "[REDACTED]"


def test_redact_artifact_nested() -> None:
    data = {"request": {"password": "p@ss", "safe": "ok"}}

    redacted = redact_artifact(data)

    assert redacted["request"]["password"] == "[REDACTED]"
    assert redacted["request"]["safe"] == "ok"


def test_redact_artifact_preserves_safe_keys() -> None:
    data = {"target_url": "https://example.com", "severity": "high"}

    redacted = redact_artifact(data)

    assert redacted["target_url"] == "https://example.com"
    assert redacted["severity"] == "high"


def test_prepare_scan_payload_includes_mode() -> None:
    scanner = LocalDevScanner(api_url="https://api.breachforge.io", token="test-token")

    payload = scanner.prepare_scan_payload("https://example.com")

    assert payload["mode"] == "local_dev"


def test_prepare_scan_payload_with_gate() -> None:
    scanner = LocalDevScanner(api_url="https://api.breachforge.io", token="test-token")

    payload = scanner.prepare_scan_payload("https://example.com", gate_path="gates/local.yaml")

    assert payload["gate_config_path"] == "gates/local.yaml"
