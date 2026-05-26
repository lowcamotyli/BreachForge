from __future__ import annotations

from api.middleware.logging import redact_for_audit


def test_redact_for_audit_strips_authorization() -> None:
    assert redact_for_audit({"authorization": "Bearer abc"}) == {"authorization": "[REDACTED]"}


def test_redact_for_audit_strips_cookie() -> None:
    assert redact_for_audit({"cookie": "session=xyz"}) == {"cookie": "[REDACTED]"}


def test_redact_for_audit_nested() -> None:
    assert redact_for_audit({"request": {"token": "abc"}}) == {"request": {"token": "[REDACTED]"}}


def test_redact_for_audit_preserves_clean() -> None:
    assert redact_for_audit({"url": "https://example.com"}) == {"url": "https://example.com"}
