from __future__ import annotations

import structlog

from execution_plane.providers.hexstrike import HexStrikeProvider
from execution_plane.providers.registry import ToolCapabilityRegistry


logger = structlog.get_logger(__name__)


def register_hexstrike_capabilities(
    registry: ToolCapabilityRegistry,
    base_url: str = "http://localhost:8888",
) -> None:
    provider = HexStrikeProvider(base_url=base_url)
    registry.register(provider)
    logger.info("hexstrike_registered", capabilities=provider.capabilities())


def get_default_registry() -> ToolCapabilityRegistry:
    return ToolCapabilityRegistry()
