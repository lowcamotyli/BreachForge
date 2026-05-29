from __future__ import annotations

import enum
from dataclasses import dataclass


class KillSwitchLevel(enum.Enum):
    SCAN = "scan"
    PROJECT = "project"
    ORG = "org"
    RUNNER = "runner"


class KillSwitch:
    """Checks and manages kill switch flags via Redis."""

    KEY_PATTERN = "kill_switch:{level}:{entity_id}"
    TTL_SECONDS = 86400

    def __init__(self, redis_client):
        self._redis = redis_client

    def _key(self, level: KillSwitchLevel, entity_id: str) -> str:
        return self.KEY_PATTERN.format(level=level.value, entity_id=entity_id)

    def activate(self, level: KillSwitchLevel, entity_id: str) -> None:
        self._redis.set(self._key(level, entity_id), "1", ex=self.TTL_SECONDS)

    def deactivate(self, level: KillSwitchLevel, entity_id: str) -> None:
        self._redis.delete(self._key(level, entity_id))

    def is_active(self, scan_id: str, project_id: str | None = None, org_id: str | None = None) -> bool:
        if self._redis.get(self._key(KillSwitchLevel.SCAN, scan_id)):
            return True
        if project_id and self._redis.get(self._key(KillSwitchLevel.PROJECT, project_id)):
            return True
        if org_id and self._redis.get(self._key(KillSwitchLevel.ORG, org_id)):
            return True
        return False
