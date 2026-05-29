from __future__ import annotations

from collections.abc import Callable
from unittest.mock import MagicMock

import pytest
from structlog.testing import capture_logs

from execution_plane.workers.supervisor import WorkerCrashError, WorkerSupervisor


class _FakeQueue:
    def __init__(self) -> None:
        self.requeued_jobs: list[_FakeJob] = []

    def enqueue_job(self, job: "_FakeJob") -> None:
        self.requeued_jobs.append(job)


class _FakeJob:
    def __init__(self, job_id: str, queue: _FakeQueue, action: Callable[[], object]) -> None:
        self.id = job_id
        self.queue = queue
        self.meta: dict[str, object] = {}
        self._action = action
        self.saved_meta = False

    def perform(self) -> object:
        return self._action()

    def save_meta(self) -> None:
        self.saved_meta = True


class _FakeRedisStream:
    def __init__(self) -> None:
        self._streams: dict[str, list[tuple[str, dict[str, str]]]] = {}

    def xadd(self, key: str, payload: dict[str, str]) -> str:
        entries = self._streams.setdefault(key, [])
        entry_id = f"{len(entries) + 1}-0"
        entries.append((entry_id, payload))
        return entry_id

    def xrange(self, key: str, start: str = "-", end: str = "+") -> list[tuple[str, dict[str, str]]]:
        del start, end
        return list(self._streams.get(key, []))


def test_simulate_crash_raises_worker_crash_error() -> None:
    supervisor = WorkerSupervisor(queues=["attack"], redis_client=MagicMock())

    with pytest.raises(WorkerCrashError) as exc_info:
        supervisor.simulate_crash("job-crash-1")

    assert exc_info.value.job_id == "job-crash-1"


def test_supervisor_requeues_job_after_crash() -> None:
    supervisor = WorkerSupervisor(queues=["attack"], redis_client=MagicMock())
    queue = _FakeQueue()
    job = _FakeJob("job-retry-1", queue, lambda: supervisor.simulate_crash("job-retry-1"))

    result = supervisor.run_with_retry(job)  # type: ignore[arg-type]

    assert result is None
    assert queue.requeued_jobs == [job]
    assert job.meta["worker_crash_retries"] == 1
    assert job.saved_meta is True


def test_redis_evidence_buffer_is_not_lost_after_crash() -> None:
    redis_stream = _FakeRedisStream()
    supervisor = WorkerSupervisor(queues=["attack"], redis_client=MagicMock())
    queue = _FakeQueue()
    scan_id = "scan-crash-1"

    def _write_evidence_then_crash() -> object:
        redis_stream.xadd(
            f"evidence:{scan_id}",
            {"attack_task_id": "task-1", "worker_id": "worker-1", "response": '{"status": 200}'},
        )
        supervisor.simulate_crash("job-evidence-1")

    job = _FakeJob("job-evidence-1", queue, _write_evidence_then_crash)

    supervisor.run_with_retry(job)  # type: ignore[arg-type]

    entries = redis_stream.xrange(f"evidence:{scan_id}")
    assert entries == [
        (
            "1-0",
            {"attack_task_id": "task-1", "worker_id": "worker-1", "response": '{"status": 200}'},
        )
    ]
    assert queue.requeued_jobs == [job]


def test_worker_crash_log_contains_job_id() -> None:
    supervisor = WorkerSupervisor(queues=["attack"], redis_client=MagicMock())
    queue = _FakeQueue()
    job = _FakeJob("job-log-1", queue, lambda: supervisor.simulate_crash("job-log-1"))

    with capture_logs() as logs:
        supervisor.run_with_retry(job)  # type: ignore[arg-type]

    assert any(entry.get("job_id") == "job-log-1" for entry in logs)
