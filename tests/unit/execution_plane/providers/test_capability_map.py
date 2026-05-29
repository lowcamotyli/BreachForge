from __future__ import annotations

import pytest

from execution_plane.providers.capability_map import (
    get_default_registry,
    register_hexstrike_capabilities,
)
from execution_plane.providers.registry import ToolCapabilityRegistry


@pytest.fixture(autouse=True)
def reset_registry() -> None:
    ToolCapabilityRegistry.reset_for_testing()


def test_register_hexstrike_capabilities_registers_provider_into_registry() -> None:
    registry = ToolCapabilityRegistry()

    register_hexstrike_capabilities(registry)

    assert registry.get("zap") is not None


def test_registered_capabilities_include_hexstrike_safe_tools() -> None:
    registry = ToolCapabilityRegistry()

    register_hexstrike_capabilities(registry)

    assert registry.get("zap") is not None
    assert registry.get("nuclei") is not None
    assert registry.get("httpx") is not None
    assert registry.get("katana") is not None


def test_get_default_registry_returns_registry_instance() -> None:
    registry = get_default_registry()

    assert isinstance(registry, ToolCapabilityRegistry)


def test_register_hexstrike_capabilities_twice_does_not_duplicate_provider() -> None:
    registry = ToolCapabilityRegistry()

    register_hexstrike_capabilities(registry)
    first_provider = registry.get("zap")
    register_hexstrike_capabilities(registry)
    second_provider = registry.get("zap")

    assert first_provider is second_provider
