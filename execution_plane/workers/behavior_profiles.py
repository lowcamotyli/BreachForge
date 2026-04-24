from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class BehaviorProfile(str, Enum):
    low_and_slow = "low_and_slow"
    burst = "burst"
    mixed = "mixed"


@dataclass(slots=True)
class BehaviorConfig:
    request_delay_ms: int
    think_time_ms: int
    jitter_pct: float
    repeatability: int = 3


def get_profile_config(profile: BehaviorProfile) -> BehaviorConfig:
    if profile is BehaviorProfile.low_and_slow:
        return BehaviorConfig(
            request_delay_ms=1200,
            think_time_ms=400,
            jitter_pct=0.15,
        )
    if profile is BehaviorProfile.burst:
        return BehaviorConfig(
            request_delay_ms=0,
            think_time_ms=10,
            jitter_pct=0.05,
        )
    return BehaviorConfig(
        request_delay_ms=300,
        think_time_ms=125,
        jitter_pct=0.10,
    )
