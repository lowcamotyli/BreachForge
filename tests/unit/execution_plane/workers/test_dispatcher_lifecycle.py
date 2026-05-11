from __future__ import annotations

import pytest

from execution_plane.workers.dispatcher import (
    DEFAULT_LIFECYCLE_SECOND_CHECK_DELAY,
    LIFECYCLE_SECOND_CHECK_CAP_SECONDS,
    _lifecycle_second_check_delay,
)


def test_lifecycle_delay_default_is_zero() -> None:
    assert _lifecycle_second_check_delay(None) == 0


def test_lifecycle_delay_empty_string_is_zero() -> None:
    assert _lifecycle_second_check_delay("") == 0


def test_lifecycle_delay_invalid_string_is_zero() -> None:
    assert _lifecycle_second_check_delay("notanumber") == 0


def test_lifecycle_delay_negative_is_zero() -> None:
    assert _lifecycle_second_check_delay("-10") == 0


def test_lifecycle_delay_valid() -> None:
    assert _lifecycle_second_check_delay("60") == 60


def test_lifecycle_delay_clamped_to_cap() -> None:
    result = _lifecycle_second_check_delay("9999")
    assert result == LIFECYCLE_SECOND_CHECK_CAP_SECONDS


def test_lifecycle_delay_at_cap() -> None:
    result = _lifecycle_second_check_delay(str(LIFECYCLE_SECOND_CHECK_CAP_SECONDS))
    assert result == LIFECYCLE_SECOND_CHECK_CAP_SECONDS
