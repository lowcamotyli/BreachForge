from __future__ import annotations

from uuid import uuid4

from control_plane.data_deletion import DataDeletionWorkflow


def test_request_deletion_creates_request_with_pending_status() -> None:
    workflow = DataDeletionWorkflow()

    request = workflow.request_deletion(uuid4(), "owner@example.com")

    assert request.status == "pending"
    assert request.completed_at is None


def test_execute_sets_status_completed_and_populates_items_deleted() -> None:
    workflow = DataDeletionWorkflow()
    request = workflow.request_deletion(uuid4(), "owner@example.com")

    completed = workflow.execute(request.request_id)

    assert completed is not None
    assert completed.status == "completed"
    assert completed.items_deleted["auth_bundles"] > 0
    assert completed.items_deleted["scan_evidence"] > 0
    assert completed.items_deleted["api_keys"] > 0


def test_get_status_returns_request_by_id() -> None:
    workflow = DataDeletionWorkflow()
    request = workflow.request_deletion(uuid4(), "owner@example.com")

    loaded = workflow.get_status(request.request_id)

    assert loaded == request


def test_list_requests_returns_all_requests_for_org() -> None:
    workflow = DataDeletionWorkflow()
    org_id = uuid4()
    request_one = workflow.request_deletion(org_id, "owner@example.com")
    request_two = workflow.request_deletion(org_id, "admin@example.com")
    workflow.request_deletion(uuid4(), "other@example.com")

    requests = workflow.list_requests(org_id)

    assert request_one in requests
    assert request_two in requests
    assert len(requests) == 2
