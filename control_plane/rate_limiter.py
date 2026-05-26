from __future__ import annotations

import os
import time
from dataclasses import dataclass

import structlog
from redis import Redis

logger = structlog.get_logger(__name__)

_TOKEN_BUCKET_SCRIPT = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])

local values = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(values[1])
local ts = tonumber(values[2])

if tokens == nil then
  tokens = capacity
end

if ts == nil then
  ts = now_ms
end

local elapsed = math.max(0, now_ms - ts) / 1000.0
local refilled = elapsed * refill_rate
if refilled > 0 then
  tokens = math.min(capacity, tokens + refilled)
end

local allowed = 0
if tokens >= 1.0 then
  tokens = tokens - 1.0
  allowed = 1
end

redis.call('HSET', key, 'tokens', tokens, 'ts', now_ms)
local ttl_ms = math.ceil((capacity / refill_rate) * 2000)
redis.call('PEXPIRE', key, ttl_ms)

return allowed
"""

_RACE_BURST_SCRIPT = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local request_count = tonumber(ARGV[4])

local values = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(values[1])
local ts = tonumber(values[2])

if tokens == nil then
  tokens = capacity
end

if ts == nil then
  ts = now_ms
end

local elapsed = math.max(0, now_ms - ts) / 1000.0
local refilled = elapsed * refill_rate
if refilled > 0 then
  tokens = math.min(capacity, tokens + refilled)
end

local allowed = 0
if tokens >= request_count then
  tokens = tokens - request_count
  allowed = 1
end

redis.call('HSET', key, 'tokens', tokens, 'ts', now_ms)
local ttl_ms = math.ceil((capacity / refill_rate) * 2000)
redis.call('PEXPIRE', key, ttl_ms)

return allowed
"""


@dataclass(slots=True)
class DomainRateLimiter:
    redis_client: Redis
    rate_limit_rps: float
    worker_rps: float
    production_safe_mode: bool
    allow_mutating_methods: bool

    # Canonical quotas:
    # - 150 requests/minute per scan+domain
    # - 30 requests/minute per scan+domain+worker
    DEFAULT_RPS = 150.0 / 60.0
    DEFAULT_WORKER_RPS = 30.0 / 60.0
    PRODUCTION_SAFE_RPS = 1.0
    RACE_MAX_BURST: int = 20
    MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    def __init__(
        self,
        redis_client: Redis,
        rate_limit_rps: float | None = None,
        worker_rps: float = DEFAULT_WORKER_RPS,
        production_safe_mode: bool | None = None,
        allow_mutating_methods: bool | None = None,
    ) -> None:
        safe_mode = _read_bool_env("PRODUCTION_SAFE_MODE") if production_safe_mode is None else production_safe_mode
        default_rps = self.PRODUCTION_SAFE_RPS if safe_mode else self.DEFAULT_RPS
        allow_mutating = (
            _read_bool_env("PRODUCTION_SAFE_ALLOW_MUTATING_METHODS", default=False)
            if allow_mutating_methods is None
            else allow_mutating_methods
        )

        self.redis_client = redis_client
        self.rate_limit_rps = float(os.getenv("RATE_LIMIT_RPS", str(default_rps))) if rate_limit_rps is None else rate_limit_rps
        self.worker_rps = worker_rps
        self.production_safe_mode = safe_mode
        self.allow_mutating_methods = allow_mutating

    def acquire(self, scan_id: str, domain: str, method: str = "GET") -> bool:
        if self.production_safe_mode and not self.allow_mutating_methods and method.upper() in self.MUTATING_METHODS:
            return False

        key = f"rate:{scan_id}:{domain}"
        return self._take_token(key=key, refill_rps=self.rate_limit_rps)

    def acquire_for_worker(self, scan_id: str, domain: str, worker_id: str, method: str = "GET") -> bool:
        if self.production_safe_mode and not self.allow_mutating_methods and method.upper() in self.MUTATING_METHODS:
            return False

        global_key = f"rate:{scan_id}:{domain}"
        worker_key = f"rate:{scan_id}:{domain}:worker:{worker_id}"

        if not self._take_token(key=global_key, refill_rps=self.rate_limit_rps):
            return False

        return self._take_token(key=worker_key, refill_rps=self.worker_rps)

    def _take_token(self, key: str, refill_rps: float) -> bool:
        capacity = max(refill_rps, 1.0)
        now_ms = int(time.time() * 1000)

        try:
            allowed = self.redis_client.eval(
                _TOKEN_BUCKET_SCRIPT,
                1,
                key,
                now_ms,
                refill_rps,
                capacity,
            )
        except Exception:
            logger.exception("rate_limiter_redis_error", key=key)
            return False

        return bool(allowed)

    def acquire_race_burst(self, scan_id: str, domain: str, request_count: int) -> bool:
        if request_count > self.RACE_MAX_BURST:
            return False

        key = f"rate:{scan_id}:{domain}:race_burst"
        capacity = float(self.RACE_MAX_BURST)
        now_ms = int(time.time() * 1000)

        try:
            allowed = self.redis_client.eval(
                _RACE_BURST_SCRIPT,
                1,
                key,
                now_ms,
                self.rate_limit_rps,
                capacity,
                request_count,
            )
            return bool(allowed)
        except Exception:
            logger.exception("rate_limiter_race_burst_error", key=key)
            return False


def _read_bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default

    normalized = value.strip().lower()
    return normalized in {"1", "true", "yes", "on"}
