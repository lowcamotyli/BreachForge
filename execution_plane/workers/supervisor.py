from __future__ import annotations

import asyncio
import json
import os
import signal
import time
from dataclasses import dataclass
from multiprocessing import Process
from urllib.parse import urlparse
from uuid import UUID, uuid4

import structlog
from redis import Redis
from rq import Queue, Worker
from rq.job import Job

from control_plane.auth_manager import SessionSnapshot
from control_plane.rate_limiter import DomainRateLimiter
from execution_plane.workers.attack_worker import AttackWorker
from execution_plane.workers.concurrency import BarrierRaceExecutor, RaceGuardrailViolation, RaceWindowConfig
from storage.db.models import AttackTask, RawProbe, Scan

logger = structlog.get_logger(__name__)


class WorkerGuardrailViolation(RuntimeError):
    pass


@dataclass(slots=True)
class WorkerProcessState:
    worker_id: str
    queue_name: str
    process: Process


class WorkerSupervisor:
    HEARTBEAT_INTERVAL_SECONDS = 30
    HARD_TASK_TIMEOUT_SECONDS = 300

    def __init__(self, queues: list[str], redis_client: Redis | None = None) -> None:
        self._redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._redis = redis_client or Redis.from_url(self._redis_url, decode_responses=True)
        self._rate_limiter = DomainRateLimiter(redis_client=self._redis)
        self._queues = queues
        self._workers: dict[str, WorkerProcessState] = {}
        self._running = False

    def start(self, workers_per_queue: int = 1) -> None:
        self._running = True
        for queue_name in self._queues:
            for index in range(workers_per_queue):
                worker_id = f"{queue_name}-{index}"
                self._spawn_worker(worker_id=worker_id, queue_name=queue_name)

    def stop(self) -> None:
        self._running = False
        for worker_id in list(self._workers.keys()):
            self._terminate_worker(worker_id)

    def health_heartbeat(self) -> None:
        while self._running:
            for worker_id in list(self._workers.keys()):
                try:
                    state = self._workers.get(worker_id)
                    if state is None:
                        continue

                    if not state.process.is_alive():
                        self.on_worker_crash(worker_id)
                        continue

                    if self._is_task_timeout_exceeded(worker_id):
                        logger.warning(
                            "worker_task_timeout_exceeded",
                            worker_id=worker_id,
                            queue=state.queue_name,
                            timeout_seconds=self.HARD_TASK_TIMEOUT_SECONDS,
                        )
                        self._terminate_worker(worker_id)
                        self._spawn_worker(worker_id=worker_id, queue_name=state.queue_name)
                except WorkerGuardrailViolation as exc:
                    state = self._workers.get(worker_id)
                    if state is None:
                        continue
                    logger.error(
                        "worker_guardrail_violation",
                        worker_id=worker_id,
                        queue=state.queue_name,
                        error=str(exc),
                    )
                    self._terminate_worker(worker_id)
                    self._spawn_worker(worker_id=worker_id, queue_name=state.queue_name)

            time.sleep(self.HEARTBEAT_INTERVAL_SECONDS)

    def on_worker_crash(self, worker_id: str) -> None:
        state = self._workers.get(worker_id)
        if state is None:
            return

        logger.error(
            "worker_crash_detected",
            worker_id=worker_id,
            queue=state.queue_name,
            exitcode=state.process.exitcode,
        )
        self._terminate_worker(worker_id)
        self._spawn_worker(worker_id=worker_id, queue_name=state.queue_name)

    def _spawn_worker(self, worker_id: str, queue_name: str) -> None:
        process = Process(
            target=_run_worker_process,
            kwargs={
                "worker_id": worker_id,
                "queue_name": queue_name,
                "redis_url": self._redis_url,
            },
            daemon=True,
            name=f"rq-worker-{worker_id}",
        )
        process.start()
        self._workers[worker_id] = WorkerProcessState(
            worker_id=worker_id,
            queue_name=queue_name,
            process=process,
        )
        logger.info("worker_started", worker_id=worker_id, queue=queue_name, pid=process.pid)

    def _terminate_worker(self, worker_id: str) -> None:
        state = self._workers.get(worker_id)
        if state is None:
            return

        process = state.process
        if process.is_alive() and process.pid is not None:
            os.kill(process.pid, signal.SIGKILL)
        process.join(timeout=2)

        self._workers.pop(worker_id, None)
        logger.info("worker_terminated", worker_id=worker_id, queue=state.queue_name)

    def _is_task_timeout_exceeded(self, worker_id: str) -> bool:
        worker_key = f"rq:worker:{worker_id}"
        current_job_id = self._redis.hget(worker_key, "current_job")
        if not current_job_id:
            return False

        try:
            job = Job.fetch(str(current_job_id), connection=self._redis)
        except Exception as exc:
            raise WorkerGuardrailViolation(
                f"failed to load current job metadata for worker={worker_id} job={current_job_id}"
            ) from exc

        started_at = job.started_at
        if started_at is None:
            raise WorkerGuardrailViolation(
                f"current job started_at missing for worker={worker_id} job={current_job_id}"
            )

        elapsed_seconds = time.time() - started_at.timestamp()
        return elapsed_seconds > self.HARD_TASK_TIMEOUT_SECONDS

    async def run_race_window(
        self,
        tasks: list[AttackTask],
        session: SessionSnapshot,
        scan: Scan,
        race_group_id: UUID | None = None,
        config: RaceWindowConfig | None = None,
    ) -> list[RawProbe]:
        if not tasks:
            return []

        if any(task.scan_id != scan.id for task in tasks):
            raise WorkerGuardrailViolation("run_race_window requires all tasks to belong to the provided scan")

        race_group_id = race_group_id or uuid4()
        worker = AttackWorker(redis_client=self._redis)
        coroutines = [worker.execute(task, session, race_group_id=race_group_id) for task in tasks]
        executor = BarrierRaceExecutor()
        results = await executor.execute_race_group(
            coroutines,
            scan_id=str(scan.id),
            domain=self._extract_domain(tasks[0]),
            race_group_id=race_group_id,
            rate_limiter=self._rate_limiter,
            config=config,
        )
        probes: list[RawProbe] = []
        exceptions: list[BaseException] = []
        for result in results:
            if isinstance(result, RawProbe):
                probes.append(result)
                continue
            if isinstance(result, BaseException):
                exceptions.append(result)
                logger.warning("race_window_task_exception", error=str(result), error_type=type(result).__name__)
                continue
            logger.warning("race_window_task_unexpected_result", result_type=type(result).__name__)

        logger.info(
            "race_window_completed",
            race_group_id=str(race_group_id),
            probes=len(probes),
            exceptions=len(exceptions),
        )
        return probes

    def _extract_domain(self, task: AttackTask) -> str:
        hypothesis = task.hypothesis
        if not hypothesis:
            return "unknown"
        try:
            parsed_hypothesis = json.loads(hypothesis)
        except json.JSONDecodeError:
            return "unknown"
        if not isinstance(parsed_hypothesis, dict):
            return "unknown"
        endpoint = parsed_hypothesis.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.strip():
            return "unknown"
        parsed_endpoint = urlparse(endpoint)
        if not parsed_endpoint.hostname:
            return "unknown"
        return parsed_endpoint.hostname.lower()


def _run_worker_process(worker_id: str, queue_name: str, redis_url: str) -> None:
    connection = Redis.from_url(redis_url, decode_responses=True)
    queue = Queue(name=queue_name, connection=connection)
    worker = Worker(queues=[queue], connection=connection, name=worker_id)
    worker.work(with_scheduler=True, logging_level="INFO")
