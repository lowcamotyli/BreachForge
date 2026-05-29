from __future__ import annotations

import time
from typing import Any

import httpx

from execution_plane.providers.base import (
    ExecutionProvider,
    ResourceBudget,
    SafetyClass,
    ToolResult,
)


class HexStrikeProvider(ExecutionProvider):
    def __init__(
        self,
        base_url: str = "http://localhost:8888",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient()

    def name(self) -> str:
        return "hexstrike"

    def capabilities(self) -> list[str]:
        return ["zap", "nuclei", "httpx", "katana"]

    def safety_class(self) -> SafetyClass:
        return SafetyClass.MEDIUM

    def resource_budget(self) -> ResourceBudget:
        return ResourceBudget(timeout_seconds=120, max_memory_mb=1024, max_requests=50)

    async def health_check(self) -> bool:
        try:
            response = await self._client.get(f"{self._base_url}/health")
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def get_version(self) -> str:
        response = await self._client.get(f"{self._base_url}/version")
        response.raise_for_status()
        payload = response.json()
        return str(payload["version"])

    async def run(self, task: dict[str, Any], context: dict[str, Any]) -> ToolResult:
        del context
        tool = str(task.get("tool", ""))
        if tool not in self.capabilities():
            raise ValueError(f"Unsupported tool: {tool}")

        started = time.monotonic()
        try:
            response = await self._client.post(
                f"{self._base_url}/tools/{tool}",
                json={"target": task.get("target"), "args": task.get("args", {})},
            )
            response.raise_for_status()
            elapsed = time.monotonic() - started

            json_output: dict[str, Any] | None
            try:
                json_output = response.json()
            except ValueError:
                json_output = None

            return ToolResult(
                stdout=response.text,
                stderr="",
                exit_code=0,
                json_output=json_output,
                elapsed_seconds=elapsed,
                provider_id="hexstrike",
            )
        except Exception as e:  # pragma: no cover - exercised by tests
            return ToolResult(
                stdout="",
                stderr=str(e),
                exit_code=1,
                json_output=None,
                elapsed_seconds=0.0,
                provider_id="hexstrike",
            )
