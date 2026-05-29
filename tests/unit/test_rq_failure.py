from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
_shadowed_pkg = sys.modules.get("execution_plane")
if _shadowed_pkg is not None and str(getattr(_shadowed_pkg, "__file__", "")).endswith(
    "tests/unit/execution_plane/__init__.py"
):
    del sys.modules["execution_plane"]

import execution_plane.workers.dispatcher as dispatcher_module
from control_plane.orchestrator import ScanOrchestrator
from execution_plane.workers.dispatcher import _finalize_scan_async, retry_on_redis_error


class _RedisStub:
    def __init__(self) -> None:
        self.calls = 0

    def setnx(self, key: str, value: str) -> bool:
        del key, value
        self.calls += 1
        return False


class _RedisRetryStore:
    def __init__(self) -> None:
        self.values: dict[str, int] = {}
        self.expire_calls: list[tuple[str, int]] = []
        self.setnx_values: dict[str, str] = {}
        self.stream: list[tuple[str, dict[str, object]]] = []

    def incr(self, key: str) -> int:
        value = self.values.get(key, 0) + 1
        self.values[key] = value
        return value

    def expire(self, key: str, ttl: int) -> None:
        self.expire_calls.append((key, ttl))

    def setnx(self, key: str, value: str) -> bool:
        if key in self.setnx_values:
            return False
        self.setnx_values[key] = value
        return True

    def xadd(self, stream_key: str, payload: dict[str, object]) -> None:
        self.stream.append((stream_key, payload))


class _QueueStub:
    def __init__(self, name: str, connection: object) -> None:
        self.name = name
        self.connection = connection
        self.enqueued: list[tuple[object, ...]] = []

    def enqueue(self, *args: object) -> None:
        self.enqueued.append(args)


@pytest.mark.asyncio
async def test_finalize_scan_is_idempotent_when_already_finalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://test")
    monkeypatch.setattr("redis.Redis.from_url", lambda *args, **kwargs: _RedisStub())
    validate_mock = AsyncMock()
    followups_mock = AsyncMock(return_value=[])
    monkeypatch.setattr(dispatcher_module, "_validate_and_score_evidence", validate_mock)
    monkeypatch.setattr(dispatcher_module, "_create_autonomous_follow_up_tasks", followups_mock)

    await _finalize_scan_async(str(uuid4()))

    validate_mock.assert_not_awaited()
    followups_mock.assert_not_awaited()


def test_retry_on_redis_error_retries_only_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda _: None)
    attempts = {"count": 0}

    @retry_on_redis_error
    def _flaky() -> str:
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RedisTimeoutError("timeout")
        return "ok"

    assert _flaky() == "ok"
    assert attempts["count"] == 3


def test_orchestrator_transient_vs_permanent_requeue(monkeypatch: pytest.MonkeyPatch) -> None:
    redis_store = _RedisRetryStore()
    monkeypatch.setenv("REDIS_URL", "redis://test")
    monkeypatch.setattr("control_plane.orchestrator.Redis.from_url", lambda _: redis_store)

    created_queues: list[_QueueStub] = []

    def _queue_factory(*, name: str, connection: object) -> _QueueStub:
        queue = _QueueStub(name=name, connection=connection)
        created_queues.append(queue)
        return queue

    monkeypatch.setattr("control_plane.orchestrator.Queue", _queue_factory)

    orchestrator = ScanOrchestrator(
        session_factory=lambda: SimpleNamespace(),
        reporting_service=SimpleNamespace(export=AsyncMock()),
    )

    queue = created_queues[0]
    transient_requeued = orchestrator.handle_rq_job_failure(
        queue=queue,
        job_callable="execution_plane.workers.dispatcher.execute_attack",
        job_id="job-1",
        args=("abc",),
        error=RedisConnectionError("conn"),
    )
    permanent_requeued = orchestrator.handle_rq_job_failure(
        queue=queue,
        job_callable="execution_plane.workers.dispatcher.execute_attack",
        job_id="job-2",
        args=("def",),
        error=ValueError("boom"),
    )
    second_transient = orchestrator.handle_rq_job_failure(
        queue=queue,
        job_callable="execution_plane.workers.dispatcher.execute_attack",
        job_id="job-1",
        args=("abc",),
        error=RedisConnectionError("conn"),
    )

    assert transient_requeued is True
    assert permanent_requeued is False
    assert second_transient is False
    assert queue.enqueued == [("execution_plane.workers.dispatcher.execute_attack", "abc")]


def test_orchestrator_finding_setnx_deduplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    redis_store = _RedisRetryStore()
    monkeypatch.setenv("REDIS_URL", "redis://test")
    monkeypatch.setattr("control_plane.orchestrator.Redis.from_url", lambda _: redis_store)
    monkeypatch.setattr(
        "control_plane.orchestrator.Queue",
        lambda *, name, connection: _QueueStub(name=name, connection=connection),
    )

    orchestrator = ScanOrchestrator(
        session_factory=lambda: SimpleNamespace(),
        reporting_service=SimpleNamespace(export=AsyncMock()),
    )

    scan_id = uuid4()
    payload = {"finding_id": "f1", "event": "finding"}
    first = orchestrator.append_finding_evidence(scan_id=scan_id, finding_id="f1", payload=payload)
    second = orchestrator.append_finding_evidence(scan_id=scan_id, finding_id="f1", payload=payload)

    assert first is True
    assert second is False
    assert len(redis_store.stream) == 1


@pytest.mark.asyncio
async def test_validate_and_score_evidence_requires_validator_output_before_scoring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ValidatorNoArtifacts:
        def __init__(self, redis_client: object, evidence_store: object) -> None:
            del redis_client, evidence_store
            self._finding_queue = None

        async def process_once(self, scan_uuid: object) -> int:
            del scan_uuid
            return 0

        def drain_feedback(self) -> list[object]:
            return []

    score_mock = AsyncMock()
    monkeypatch.setattr("execution_plane.validator.validator.ExploitValidator", _ValidatorNoArtifacts)
    monkeypatch.setattr("control_plane.finding_scorer._score_artifact_async", score_mock)

    logger = SimpleNamespace(info=lambda *args, **kwargs: None)
    await dispatcher_module._validate_and_score_evidence(
        scan_uuid=uuid4(),
        redis_connection=SimpleNamespace(),
        logger=logger,
    )

    score_mock.assert_not_awaited()
