from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import TypeVar

T = TypeVar("T")


class ParallelBurstExecutor:
    async def execute_burst(self, tasks: list[Awaitable[T]], window_seconds: float) -> list[T]:
        if not tasks:
            return []

        timeout_seconds = max(window_seconds, 0.0)
        burst = asyncio.gather(*tasks)
        results = await asyncio.wait_for(burst, timeout=timeout_seconds)
        return list(results)
