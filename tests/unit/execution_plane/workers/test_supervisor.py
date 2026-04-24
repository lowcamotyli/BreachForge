from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[4]
SUPERVISOR_PATH = PROJECT_ROOT / "execution_plane/workers/supervisor.py"


def _load_supervisor_module() -> ModuleType:
    redis_module = ModuleType("redis")
    redis_module.Redis = type("Redis", (), {"from_url": staticmethod(lambda *args, **kwargs: MagicMock())})

    rq_module = ModuleType("rq")
    rq_module.Queue = type("Queue", (), {"__init__": lambda self, *args, **kwargs: None})
    rq_module.Worker = type(
        "Worker",
        (),
        {"__init__": lambda self, *args, **kwargs: None, "work": lambda self, **kwargs: None},
    )

    rq_job_module = ModuleType("rq.job")
    rq_job_module.Job = type("Job", (), {"fetch": staticmethod(lambda *args, **kwargs: MagicMock(started_at=None))})

    sys.modules.setdefault("redis", redis_module)
    sys.modules.setdefault("rq", rq_module)
    sys.modules.setdefault("rq.job", rq_job_module)

    spec = importlib.util.spec_from_file_location("project_supervisor", SUPERVISOR_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


supervisor_module = _load_supervisor_module()
WorkerGuardrailViolation = supervisor_module.WorkerGuardrailViolation
WorkerProcessState = supervisor_module.WorkerProcessState
WorkerSupervisor = supervisor_module.WorkerSupervisor


class _FakeProcess:
    def __init__(self, *, alive: bool, pid: int | None = 123, exitcode: int | None = None) -> None:
        self._alive = alive
        self.pid = pid
        self.exitcode = exitcode
        self.join_calls = 0

    def is_alive(self) -> bool:
        return self._alive

    def join(self, timeout: int | float | None = None) -> None:
        self.join_calls += 1
        self._alive = False


def test_on_worker_crash_restarts_worker_deterministically() -> None:
    redis_client = MagicMock()
    supervisor = WorkerSupervisor(queues=["attack"], redis_client=redis_client)

    crashed_process = _FakeProcess(alive=False, exitcode=137)
    supervisor._workers["attack-0"] = WorkerProcessState(
        worker_id="attack-0",
        queue_name="attack",
        process=crashed_process,
    )

    terminated: list[str] = []
    spawned: list[tuple[str, str]] = []
    supervisor._terminate_worker = lambda worker_id: terminated.append(worker_id)  # type: ignore[assignment]
    supervisor._spawn_worker = lambda worker_id, queue_name: spawned.append((worker_id, queue_name))  # type: ignore[assignment]

    supervisor.on_worker_crash("attack-0")

    assert terminated == ["attack-0"]
    assert spawned == [("attack-0", "attack")]


def test_is_task_timeout_exceeded_raises_on_job_fetch_failure() -> None:
    redis_client = MagicMock()
    redis_client.hget.return_value = "job-1"
    supervisor = WorkerSupervisor(queues=["attack"], redis_client=redis_client)

    def _raise_fetch(*args: object, **kwargs: object) -> object:
        raise RuntimeError("redis error")

    original_fetch = supervisor_module.Job.fetch
    supervisor_module.Job.fetch = _raise_fetch
    try:
        with pytest.raises(WorkerGuardrailViolation):
            supervisor._is_task_timeout_exceeded("attack-0")
    finally:
        supervisor_module.Job.fetch = original_fetch


def test_is_task_timeout_exceeded_raises_when_started_at_missing() -> None:
    redis_client = MagicMock()
    redis_client.hget.return_value = "job-1"
    supervisor = WorkerSupervisor(queues=["attack"], redis_client=redis_client)

    job = MagicMock()
    job.started_at = None
    original_fetch = supervisor_module.Job.fetch
    supervisor_module.Job.fetch = lambda *args, **kwargs: job
    try:
        with pytest.raises(WorkerGuardrailViolation):
            supervisor._is_task_timeout_exceeded("attack-0")
    finally:
        supervisor_module.Job.fetch = original_fetch


def test_health_heartbeat_fail_closed_on_guardrail_violation(monkeypatch: pytest.MonkeyPatch) -> None:
    redis_client = MagicMock()
    supervisor = WorkerSupervisor(queues=["attack"], redis_client=redis_client)
    supervisor._workers["attack-0"] = WorkerProcessState(
        worker_id="attack-0",
        queue_name="attack",
        process=_FakeProcess(alive=True),
    )
    supervisor._running = True

    calls: list[str] = []
    supervisor._is_task_timeout_exceeded = lambda worker_id: (_ for _ in ()).throw(  # type: ignore[assignment]
        WorkerGuardrailViolation("guardrail")
    )
    supervisor._terminate_worker = lambda worker_id: calls.append(f"terminate:{worker_id}")  # type: ignore[assignment]
    supervisor._spawn_worker = lambda worker_id, queue_name: calls.append(f"spawn:{worker_id}:{queue_name}")  # type: ignore[assignment]

    def _sleep_once(seconds: int | float) -> None:
        supervisor._running = False

    monkeypatch.setattr(supervisor_module.time, "sleep", _sleep_once)

    supervisor.health_heartbeat()

    assert calls == ["terminate:attack-0", "spawn:attack-0:attack"]


def test_terminate_worker_joins_even_when_process_not_alive() -> None:
    redis_client = MagicMock()
    supervisor = WorkerSupervisor(queues=["attack"], redis_client=redis_client)
    process = _FakeProcess(alive=False, pid=None)
    supervisor._workers["attack-0"] = WorkerProcessState(
        worker_id="attack-0",
        queue_name="attack",
        process=process,
    )

    supervisor._terminate_worker("attack-0")

    assert process.join_calls == 1
    assert "attack-0" not in supervisor._workers
