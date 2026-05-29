from __future__ import annotations

from collections.abc import Iterable
from threading import Lock
from typing import ClassVar

from execution_plane.providers.base import ExecutionProvider


SUPPORTED_CAPABILITIES: tuple[str, ...] = (
    "zap",
    "nuclei",
    "httpx",
    "katana",
    "hexstrike_proxy",
)


class ToolCapabilityRegistry:
    _instance: ClassVar[ToolCapabilityRegistry | None] = None
    _instance_lock: ClassVar[Lock] = Lock()
    _providers: dict[str, ExecutionProvider]

    def __new__(cls) -> ToolCapabilityRegistry:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._providers = {}
        return cls._instance

    def register(self, provider: ExecutionProvider) -> None:
        for capability in self._supported(provider.capabilities()):
            self._providers.setdefault(capability, provider)

    def get(self, capability: str) -> ExecutionProvider | None:
        if capability not in SUPPORTED_CAPABILITIES:
            return None
        return self._providers.get(capability)

    def list_capabilities(self) -> list[str]:
        return [
            capability
            for capability in SUPPORTED_CAPABILITIES
            if capability in self._providers
        ]

    @classmethod
    def reset_for_testing(cls) -> None:
        cls()._providers.clear()

    @staticmethod
    def supported_capabilities() -> list[str]:
        return list(SUPPORTED_CAPABILITIES)

    @staticmethod
    def _supported(capabilities: Iterable[str]) -> list[str]:
        return [
            capability
            for capability in capabilities
            if capability in SUPPORTED_CAPABILITIES
        ]
