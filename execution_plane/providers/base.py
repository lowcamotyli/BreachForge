from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any


class SafetyClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    timeout_seconds: int = 300
    max_memory_mb: int = 512
    max_requests: int = 1


@dataclass(frozen=True, slots=True)
class ToolResult:
    stdout: str
    stderr: str
    exit_code: int
    json_output: dict[str, Any] | None
    elapsed_seconds: float
    provider_id: str


class ExecutionProvider(ABC):
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def capabilities(self) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def safety_class(self) -> SafetyClass:
        raise NotImplementedError

    @abstractmethod
    def resource_budget(self) -> ResourceBudget:
        raise NotImplementedError

    @abstractmethod
    async def run(self, task: dict[str, Any], context: dict[str, Any]) -> ToolResult:
        raise NotImplementedError
