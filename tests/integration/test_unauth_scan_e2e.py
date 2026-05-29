from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

import control_plane.orchestrator as orchestrator_module
from control_plane.orchestrator import ScanOrchestrator
from execution_plane.planner.planner import AttackPlanner
from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AssetMap as DbAssetMap
from storage.db.models import AttackTask, AuditEvent, Endpoint, Scan, ScanStatus, Target

# Existing credential-auth tests should continue to pass; this file only covers the unauth_mode branch.


class _QueueStub:
    def __init__(self, name: str, connection: object) -> None:
        self.name = name
        self.connection = connection
        self.enqueued: list[tuple[object, ...]] = []

    def enqueue(self, *args: object) -> None:
        self.enqueued.append(args)


class _ScalarResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _SessionStub:
    def __init__(self, scan: Scan, committed_phases: list[tuple[ScanStatus, str | None]]) -> None:
        self._scan = scan
        self._committed_phases = committed_phases

    async def __aenter__(self) -> _SessionStub:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    async def execute(self, statement: object) -> _ScalarResult:
        del statement
        return _ScalarResult(self._scan)

    def add(self, obj: object) -> None:
        assert isinstance(obj, AuditEvent)

    async def commit(self) -> None:
        self._committed_phases.append((self._scan.status, self._scan.phase))


class _SessionFactoryStub:
    def __init__(self, scan: Scan) -> None:
        self.scan = scan
        self.committed_phases: list[tuple[ScanStatus, str | None]] = []

    def __call__(self) -> _SessionStub:
        return _SessionStub(self.scan, self.committed_phases)


class _PublicRule(AttackRule):
    requires_auth = False
    attack_class = "public_probe"
    name = "PublicRule"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del endpoint, asset_map
        return True

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="response",
                hypothesis="public unauth task",
            )
        ]

    def expected_proof_signal(self) -> str:
        return "public endpoint is testable without credentials"


class _AuthenticatedRule(_PublicRule):
    requires_auth = True
    attack_class = "auth_only_probe"
    name = "AuthenticatedRule"


def _build_scan_without_auth_context(scan_id: UUID) -> Scan:
    target_id = uuid4()
    target = Target(
        id=target_id,
        url="https://public.example.test",
        name="public-target",
        config={
            "unauth_mode": True,
            "spec_asset_map": {
                "target_url": "https://public.example.test",
                "endpoints": [
                    {
                        "url_pattern": "/api/public/config",
                        "method": "GET",
                        "auth_required": False,
                        "parameters": [],
                        "observed_content_type": "application/json",
                        "example_response_code": 200,
                    }
                ],
            },
        },
    )
    scan = Scan(id=scan_id, target_id=target_id, status=ScanStatus.created, phase=None)
    scan.target = target
    scan.auth_context = None
    scan.asset_map = None
    return scan


def _build_orchestrator(
    monkeypatch: pytest.MonkeyPatch,
    session_factory: _SessionFactoryStub,
) -> tuple[ScanOrchestrator, _QueueStub, _QueueStub, _QueueStub]:
    monkeypatch.setenv("REDIS_URL", "redis://test")
    monkeypatch.setattr(orchestrator_module.Redis, "from_url", lambda _: object())

    created_queues: list[_QueueStub] = []

    def _queue_factory(*, name: str, connection: object) -> _QueueStub:
        queue = _QueueStub(name=name, connection=connection)
        created_queues.append(queue)
        return queue

    monkeypatch.setattr(orchestrator_module, "Queue", _queue_factory)
    orchestrator = ScanOrchestrator(
        session_factory=session_factory,
        reporting_service=SimpleNamespace(export=AsyncMock()),
    )
    return orchestrator, created_queues[0], created_queues[1], created_queues[2]


@pytest.mark.asyncio
async def test_unauth_scan_without_auth_context_completes_fsm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = uuid4()
    session_factory = _SessionFactoryStub(_build_scan_without_auth_context(scan_id))
    orchestrator, auth_queue, attack_queue, recon_queue = _build_orchestrator(monkeypatch, session_factory)
    monkeypatch.setattr(orchestrator_module, "purge_scan_credentials", AsyncMock())

    await orchestrator.on_scan_created(scan_id)
    await orchestrator.on_attack_complete(scan_id)
    await orchestrator.on_all_validated(scan_id)

    assert auth_queue.enqueued == []
    assert recon_queue.enqueued == []
    assert attack_queue.enqueued == [
        (
            orchestrator._attack_planning_job,
            str(scan_id),
            {
                "target_url": "https://public.example.test",
                "endpoints": [
                    {
                        "url_pattern": "/api/public/config",
                        "method": "GET",
                        "auth_required": False,
                        "parameters": [],
                        "observed_content_type": "application/json",
                        "example_response_code": 200,
                    }
                ],
            },
        )
    ]
    assert session_factory.scan.auth_context is None
    assert session_factory.committed_phases == [
        (ScanStatus.running, "recon"),
        (ScanStatus.running, "recon"),
        (ScanStatus.running, "attack"),
        (ScanStatus.running, "validate"),
        (ScanStatus.running, "reporting"),
        (ScanStatus.complete, "complete"),
    ]


def test_planner_unauth_mode_filters_rules_that_require_auth() -> None:
    scan_id = uuid4()
    asset_map = DbAssetMap(id=uuid4(), scan_id=scan_id)
    endpoint = Endpoint(
        id=uuid4(),
        asset_map_id=asset_map.id,
        url_pattern="/api/public/config",
        method="GET",
        auth_required=False,
        parameters=[],
        observed_content_type="application/json",
        example_response_code=200,
    )
    asset_map.endpoints = [endpoint]

    planner = AttackPlanner()
    planner.rules = [_PublicRule(), _AuthenticatedRule()]
    planner.playbooks = []

    tasks = planner.plan(
        ScanContext(scan_id=scan_id, target_url="https://public.example.test", asset_map=asset_map),
        unauth_mode=True,
    )

    assert tasks
    assert {task.attack_class for task in tasks} == {"public_probe"}
