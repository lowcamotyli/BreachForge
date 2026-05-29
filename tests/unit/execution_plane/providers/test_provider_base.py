from __future__ import annotations

import pytest

from execution_plane.providers import (
    ExecutionProvider,
    ResourceBudget,
    SafetyClass,
    ToolCapabilityRegistry,
    ToolResult,
)


class DummyProvider(ExecutionProvider):
    def __init__(self, provider_name: str, provider_capabilities: list[str]) -> None:
        self._provider_name = provider_name
        self._provider_capabilities = provider_capabilities

    def name(self) -> str:
        return self._provider_name

    def capabilities(self) -> list[str]:
        return self._provider_capabilities

    def safety_class(self) -> SafetyClass:
        return SafetyClass.LOW

    def resource_budget(self) -> ResourceBudget:
        return ResourceBudget()

    async def run(
        self,
        task: dict[str, object],
        context: dict[str, object],
    ) -> ToolResult:
        return ToolResult(
            stdout="ok",
            stderr="",
            exit_code=0,
            json_output={"task": task, "context": context},
            elapsed_seconds=0.1,
            provider_id=self.name(),
        )


def test_safety_class_values() -> None:
    assert SafetyClass.LOW.value == "low"
    assert SafetyClass.MEDIUM.value == "medium"
    assert SafetyClass.HIGH.value == "high"


def test_resource_budget_defaults() -> None:
    budget = ResourceBudget()

    assert budget.timeout_seconds == 300
    assert budget.max_memory_mb == 512
    assert budget.max_requests == 1


def test_tool_result_fields() -> None:
    result = ToolResult(
        stdout="out",
        stderr="err",
        exit_code=2,
        json_output={"key": "value"},
        elapsed_seconds=1.25,
        provider_id="dummy",
    )

    assert result.stdout == "out"
    assert result.stderr == "err"
    assert result.exit_code == 2
    assert result.json_output == {"key": "value"}
    assert result.elapsed_seconds == 1.25
    assert result.provider_id == "dummy"


def test_execution_provider_is_abstract() -> None:
    with pytest.raises(TypeError):
        ExecutionProvider()


def test_registry_register_get_and_list() -> None:
    registry = ToolCapabilityRegistry()
    registry.reset_for_testing()
    provider = DummyProvider("dummy", ["zap", "httpx", "unsupported"])

    registry.register(provider)

    assert registry.get("zap") is provider
    assert registry.get("httpx") is provider
    assert registry.list_capabilities() == ["zap", "httpx"]


def test_registry_returns_none_for_unknown_capability() -> None:
    registry = ToolCapabilityRegistry()
    registry.reset_for_testing()

    assert registry.get("unknown") is None
