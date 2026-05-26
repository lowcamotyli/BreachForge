from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

import execution_plane.workers.dispatcher as dispatcher_module
from storage.db.models import AttackTask, AttackTaskStatus
from execution_plane.workers.dispatcher import (
    DEFAULT_LIFECYCLE_SECOND_CHECK_DELAY,
    LIFECYCLE_SECOND_CHECK_CAP_SECONDS,
    _dispatch_attack_tasks_async,
    _lifecycle_second_check_delay,
)


def test_lifecycle_delay_default_is_zero() -> None:
    assert _lifecycle_second_check_delay(None) == 0


def test_lifecycle_delay_empty_string_is_zero() -> None:
    assert _lifecycle_second_check_delay("") == 0


def test_lifecycle_delay_invalid_string_is_zero() -> None:
    assert _lifecycle_second_check_delay("notanumber") == 0


def test_lifecycle_delay_negative_is_zero() -> None:
    assert _lifecycle_second_check_delay("-10") == 0


def test_lifecycle_delay_valid() -> None:
    assert _lifecycle_second_check_delay("60") == 60


def test_lifecycle_delay_clamped_to_cap() -> None:
    result = _lifecycle_second_check_delay("9999")
    assert result == LIFECYCLE_SECOND_CHECK_CAP_SECONDS


def test_lifecycle_delay_at_cap() -> None:
    result = _lifecycle_second_check_delay(str(LIFECYCLE_SECOND_CHECK_CAP_SECONDS))
    assert result == LIFECYCLE_SECOND_CHECK_CAP_SECONDS


@pytest.mark.asyncio
async def test_dispatch_respects_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = str(uuid4())
    scan_uuid = uuid4()
    task = AttackTask(
        id=uuid4(),
        scan_id=scan_uuid,
        endpoint_id=uuid4(),
        attack_class="bola",
        target_parameter="user_id",
        hypothesis="{}",
        priority_score=1.0,
        status=AttackTaskStatus.pending,
    )

    class _ScalarResult:
        def __init__(self, rows: list[object]) -> None:
            self._rows = rows

        def scalars(self) -> _ScalarResult:
            return self

        def all(self) -> list[object]:
            return self._rows

    class _FakeSession:
        def __init__(self, rows: list[object]) -> None:
            self._rows = rows

        async def __aenter__(self) -> _FakeSession:
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def execute(self, stmt: object) -> _ScalarResult:
            return _ScalarResult(self._rows)

        def add(self, obj: object) -> None:
            return None

        async def commit(self) -> None:
            return None

    class _SessionFactory:
        def __call__(self) -> _FakeSession:
            return _FakeSession([task])

    class _FakeRedis:
        def get(self, key: str) -> str | None:
            if key == f"kill:{scan_id}":
                return "1"
            return None

    class _FakeQueue:
        def __init__(self, *args, **kwargs) -> None:
            self.enqueued: list[tuple[object, ...]] = []

        def enqueue(self, *args: object, **kwargs: object) -> object:
            self.enqueued.append(args)
            return SimpleNamespace()

    class _FakeAuthManager:
        def __init__(self, *args, **kwargs) -> None:
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr("storage.db.session.AsyncSessionLocal", _SessionFactory())
    monkeypatch.setattr("redis.Redis.from_url", lambda *args, **kwargs: _FakeRedis())
    fake_queue = _FakeQueue()
    monkeypatch.setattr("rq.Queue", lambda *args, **kwargs: fake_queue)
    monkeypatch.setattr("control_plane.auth_manager.AuthManager", _FakeAuthManager)
    monkeypatch.setattr("control_plane.auth_manager.default_pause_scan", lambda *args, **kwargs: None)
    monkeypatch.setattr(dispatcher_module, "_collect_expired_identity_names", AsyncMock(return_value=set()))

    await _dispatch_attack_tasks_async(scan_id)

    assert fake_queue.enqueued == []
