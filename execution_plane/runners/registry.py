from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4


@dataclass
class RunnerCapabilities:
    attack_classes: list[str] = field(default_factory=list)
    max_concurrent_jobs: int = 1
    platform: str = "linux"
    runner_version: str = "1.0.0"
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunnerRegistration:
    runner_id: UUID
    org_id: UUID
    name: str
    token_hash: str
    token_prefix: str
    capabilities: RunnerCapabilities
    registered_at: datetime
    last_heartbeat_at: datetime | None = None
    is_online: bool = False
    current_job_id: UUID | None = None
    version: str = "1.0.0"


class RunnerRegistry:
    """In-memory runner registry. Backed by DB in production."""

    def __init__(self) -> None:
        self._runners: dict[UUID, RunnerRegistration] = {}

    def register(self, org_id: UUID, name: str, capabilities: RunnerCapabilities) -> tuple[RunnerRegistration, str]:
        runner_id = uuid4()
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        token_prefix = raw_token[:8] + "..."
        now = datetime.now(UTC)
        reg = RunnerRegistration(
            runner_id=runner_id,
            org_id=org_id,
            name=name,
            token_hash=token_hash,
            token_prefix=token_prefix,
            capabilities=capabilities,
            registered_at=now,
            is_online=True,
            last_heartbeat_at=now,
        )
        self._runners[runner_id] = reg
        return reg, raw_token

    def heartbeat(self, runner_id: UUID, current_job_id: UUID | None = None) -> bool:
        reg = self._runners.get(runner_id)
        if reg is None:
            return False
        reg.last_heartbeat_at = datetime.now(UTC)
        reg.is_online = True
        reg.current_job_id = current_job_id
        return True

    def get(self, runner_id: UUID) -> RunnerRegistration | None:
        return self._runners.get(runner_id)

    def list_for_org(self, org_id: UUID) -> list[RunnerRegistration]:
        return [runner for runner in self._runners.values() if runner.org_id == org_id]

    def deregister(self, runner_id: UUID) -> bool:
        if runner_id not in self._runners:
            return False
        del self._runners[runner_id]
        return True

    def authenticate_token(self, raw_token: str) -> RunnerRegistration | None:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        for reg in self._runners.values():
            if reg.token_hash == token_hash:
                return reg
        return None
