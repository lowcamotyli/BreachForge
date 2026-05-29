from __future__ import annotations

import pytest
from pydantic import ValidationError

from execution_plane.providers.schemas import (
    HttpxArgs,
    KatanaArgs,
    NucleiArgs,
    ZapArgs,
)


def test_zap_args_has_no_additional_args_field() -> None:
    assert "additional_args" not in ZapArgs.model_fields

    with pytest.raises(ValidationError):
        ZapArgs(target_url="https://example.com", additional_args="; rm -rf /")


def test_nuclei_args_severity_rejects_invalid_values() -> None:
    with pytest.raises(ValidationError):
        NucleiArgs(target_url="https://example.com", severity=["severe"])


@pytest.mark.parametrize("method", ["DELETE", "PUT"])
def test_httpx_args_methods_rejects_delete_and_put(method: str) -> None:
    with pytest.raises(ValidationError):
        HttpxArgs(target_url="https://example.com", methods=[method])


def test_katana_args_max_depth_rejects_values_greater_than_five() -> None:
    with pytest.raises(ValidationError):
        KatanaArgs(target_url="https://example.com", max_depth=6)
