from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Any, TypeVar
from uuid import UUID

RACE_MAX_REQUESTS: int = 20

T = TypeVar("T")


@dataclass(slots=True)
class RaceWindowConfig:
    max_requests: int = RACE_MAX_REQUESTS
    window_seconds: float = 2.0
    require_mutating_policy: bool = True


class RaceGuardrailViolation(RuntimeError):
    pass


class BarrierRaceExecutor:
    async def execute_race_group(
        self,
        tasks: list[Awaitable[T]],
        scan_id: str,
        domain: str,
        race_group_id: UUID,
        rate_limiter: Any,
        config: RaceWindowConfig | None = None,
    ) -> list[T | BaseException]:
        cfg = config or RaceWindowConfig()
        if len(tasks) > cfg.max_requests:
            raise RaceGuardrailViolation(f"race group size {len(tasks)} exceeds max_requests={cfg.max_requests}")

        if not rate_limiter.acquire_race_burst(scan_id, domain, len(tasks)):
            raise RaceGuardrailViolation(f"race burst denied by rate limiter for scan={scan_id} domain={domain}")

        barrier = asyncio.Barrier(len(tasks)) if len(tasks) > 1 else None

        async def _with_barrier(coro: Awaitable[T]) -> T:
            if barrier is not None:
                await barrier.wait()
            return await coro

        results = await asyncio.gather(*[_with_barrier(t) for t in tasks], return_exceptions=True)
        return list(results)


class ParallelBurstExecutor:
    async def execute_burst(self, tasks: list[Awaitable[T]], window_seconds: float) -> list[T]:
        if not tasks:
            return []

        timeout_seconds = max(window_seconds, 0.0)
        burst = asyncio.gather(*tasks)
        results = await asyncio.wait_for(burst, timeout=timeout_seconds)
        return list(results)
