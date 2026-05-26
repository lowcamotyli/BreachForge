from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, call
from uuid import uuid4

import pytest

import control_plane.orchestrator as orchestrator_module
from control_plane.orchestrator import ScanConfig, ScanOrchestrator, log_audit_event
from storage.db.models import AuditEvent, AuditEventType, ScanStatus


class _QueueStub:
    def __init__(self, name: str, connection: object) -> None:
        self.name = name
        self.connection = connection
        self.enqueued: list[tuple[object, ...]] = []

    def enqueue(self, *args: object) -> None:
        self.enqueued.append(args)


def _build_orchestrator(monkeypatch: pytest.MonkeyPatch) -> tuple[ScanOrchestrator, _QueueStub, _QueueStub]:
    monkeypatch.setenv("REDIS_URL", "redis://test")
    monkeypatch.setattr(orchestrator_module.Redis, "from_url", lambda _: object())

    created_queues: list[_QueueStub] = []

    def _queue_factory(*, name: str, connection: object) -> _QueueStub:
        queue = _QueueStub(name=name, connection=connection)
        created_queues.append(queue)
        return queue

    monkeypatch.setattr(orchestrator_module, "Queue", _queue_factory)
    reporting_service = SimpleNamespace(export=AsyncMock())
    orchestrator = ScanOrchestrator(
        session_factory=SimpleNamespace(),
        reporting_service=reporting_service,
    )
    return orchestrator, created_queues[0], created_queues[1]


@pytest.mark.asyncio
async def test_runtime_fsm_uses_running_and_complete_with_explicit_phase_transitions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = uuid4()
    orchestrator, auth_queue, attack_queue = _build_orchestrator(monkeypatch)
    orchestrator._update_scan = AsyncMock()
    orchestrator._resolve_scan_runtime = AsyncMock(
        return_value=(ScanConfig(unauth_mode=False), False, False, None)
    )
    monkeypatch.setattr(orchestrator_module, "purge_scan_credentials", AsyncMock())

    await orchestrator.on_scan_created(scan_id)
    await orchestrator.on_recon_complete(scan_id, {"endpoints": []})
    await orchestrator.on_attack_complete(scan_id)
    await orchestrator.on_all_validated(scan_id)

    assert auth_queue.enqueued == [(orchestrator._auth_bootstrap_job, str(scan_id))]
    assert attack_queue.enqueued == [(orchestrator._attack_planning_job, str(scan_id), {"endpoints": []})]

    assert orchestrator._update_scan.await_args_list == [
        call(scan_id, status=ScanStatus.running, phase="recon", started_at=ANY),
        call(scan_id, status=ScanStatus.running, phase="attack"),
        call(scan_id, status=ScanStatus.running, phase="validate"),
        call(scan_id, status=ScanStatus.running, phase="reporting"),
        call(scan_id, status=ScanStatus.complete, phase="complete", completed_at=ANY),
    ]


@pytest.mark.asyncio
async def test_pause_scan_sets_paused_status(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_id = uuid4()
    orchestrator, _, _ = _build_orchestrator(monkeypatch)
    orchestrator._update_scan = AsyncMock()

    await orchestrator.pause_scan(scan_id, "auth_expired")

    orchestrator._update_scan.assert_awaited_once_with(
        scan_id,
        status=ScanStatus.paused,
        phase="paused:auth_expired",
    )


@pytest.mark.asyncio
async def test_log_audit_event_strips_credentials() -> None:
    captured: list[AuditEvent] = []

    class _SessionStub:
        def add(self, obj: object) -> None:
            assert isinstance(obj, AuditEvent)
            captured.append(obj)

        async def commit(self) -> None:
            return None

    session = _SessionStub()
    scan_id = uuid4()
    await log_audit_event(
        session=session,  # type: ignore[arg-type]
        scan_id=scan_id,
        event_type=AuditEventType.POLICY_VIOLATION,
        details={"authorization": "Bearer secret-token", "nested": {"cookie": "abc", "ok": "1"}},
    )

    assert len(captured) == 1
    assert captured[0].details == {"authorization": "[REDACTED]", "nested": {"cookie": "[REDACTED]", "ok": "1"}}


@pytest.mark.asyncio
async def test_log_audit_event_no_commit() -> None:
    captured: list[AuditEvent] = []

    class _SessionStub:
        def __init__(self) -> None:
            self.commit = AsyncMock()

        def add(self, obj: object) -> None:
            assert isinstance(obj, AuditEvent)
            captured.append(obj)

    session = _SessionStub()
    await log_audit_event(
        session=session,  # type: ignore[arg-type]
        scan_id=uuid4(),
        event_type=AuditEventType.SCAN_CREATED,
        details={"ok": "value"},
    )

    assert len(captured) == 1
    session.commit.assert_not_called()
