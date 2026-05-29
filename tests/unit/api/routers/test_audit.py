from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies.auth import VerifiedActor
from api.routers.audit import append_audit_event, list_audit_events, router
from storage.db.models import OrgAuditEvent, OrgRole


class _ScalarRows:
    def __init__(self, rows: list[OrgAuditEvent]) -> None:
        self._rows = rows

    def scalars(self) -> _ScalarRows:
        return self

    def all(self) -> list[OrgAuditEvent]:
        return self._rows


@pytest.fixture
def mock_db() -> AsyncMock:
    return AsyncMock(spec=AsyncSession)


@pytest.mark.asyncio
async def test_append_audit_event_inserts_with_org_id(mock_db: AsyncMock) -> None:
    assert router is not None
    org_id = uuid4()

    await append_audit_event(
        db=mock_db,
        org_id=org_id,
        event_type="api_key.created",
        actor_email="admin@example.com",
        resource_type="api_key",
        resource_id="key-1",
        details={"source": "unit"},
    )

    mock_db.add.assert_called_once()
    added_event = mock_db.add.call_args.args[0]
    assert isinstance(added_event, OrgAuditEvent)
    assert added_event.org_id == org_id
    assert added_event.event_type == "api_key.created"
    assert added_event.actor_email == "admin@example.com"
    assert added_event.resource_type == "api_key"
    assert added_event.resource_id == "key-1"
    assert added_event.details == {"source": "unit"}
    mock_db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_list_audit_events_filters_by_org_id(mock_db: AsyncMock) -> None:
    org_a_id = uuid4()
    org_b_id = uuid4()
    created_at = datetime(2026, 5, 29, 12, 0, tzinfo=UTC)
    org_a_event = OrgAuditEvent(
        id=uuid4(),
        org_id=org_a_id,
        event_type="scan.created",
        actor_email="a@example.com",
        resource_type="scan",
        resource_id="scan-a",
        details={"scan_id": "scan-a"},
        created_at=created_at,
    )
    org_b_event = OrgAuditEvent(
        id=uuid4(),
        org_id=org_b_id,
        event_type="scan.created",
        actor_email="b@example.com",
        resource_type="scan",
        resource_id="scan-b",
        details={"scan_id": "scan-b"},
        created_at=created_at,
    )
    # Mock returns only org_a events — simulates DB WHERE org_id = org_a_id
    mock_db.execute.return_value = _ScalarRows([org_a_event])
    _ = org_b_event  # constructed to verify it's not injected into mock

    events = await list_audit_events(
        org_id=org_a_id,
        actor=VerifiedActor(org_id=org_a_id, email="admin@example.com", role=OrgRole.owner),
        db=mock_db,
    )

    assert [event.org_id for event in events] == [org_a_id]
    assert events[0].event_id == org_a_event.id
    assert events[0].actor == "a@example.com"
    assert events[0].action == "scan.created"
    assert events[0].created_at == created_at
    assert events[0].metadata == {"scan_id": "scan-a"}
    mock_db.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_list_audit_events_empty_for_unknown_org(mock_db: AsyncMock) -> None:
    unknown_org_id = uuid4()
    existing_org_id = uuid4()
    existing_event = OrgAuditEvent(
        id=uuid4(),
        org_id=existing_org_id,
        event_type="member.added",
        actor_email="owner@example.com",
        resource_type="member",
        resource_id="dev@example.com",
        details={"role": "developer"},
        created_at=datetime(2026, 5, 29, 13, 0, tzinfo=UTC),
    )
    # Mock returns empty — simulates DB WHERE org_id = unknown_org_id → no rows
    mock_db.execute.return_value = _ScalarRows([])
    _ = existing_event  # belongs to a different org, not returned by DB

    events = await list_audit_events(
        org_id=unknown_org_id,
        actor=VerifiedActor(org_id=unknown_org_id, email="admin@example.com", role=OrgRole.owner),
        db=mock_db,
    )

    assert events == []
    mock_db.execute.assert_awaited_once()
