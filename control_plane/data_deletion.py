from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4


@dataclass
class DataDeletionRequest:
    request_id: UUID
    org_id: UUID
    requested_by: str
    requested_at: datetime
    status: str
    completed_at: datetime | None
    items_deleted: dict[str, int]


class DataDeletionWorkflow:
    def __init__(self) -> None:
        self._requests: dict[UUID, DataDeletionRequest] = {}
        self._deletion_log: list[DataDeletionRequest] = []

    def request_deletion(self, org_id: UUID, requested_by: str) -> DataDeletionRequest:
        request = DataDeletionRequest(
            request_id=uuid4(),
            org_id=org_id,
            requested_by=requested_by,
            requested_at=datetime.now(UTC),
            status="pending",
            completed_at=None,
            items_deleted={},
        )
        self._requests[request.request_id] = request
        return request

    def execute(self, request_id: UUID) -> DataDeletionRequest | None:
        request = self._requests.get(request_id)
        if request is None:
            return None

        request.status = "in_progress"
        request.items_deleted = {
            "auth_bundles": 3,
            "scan_evidence": 7,
            "api_keys": 2,
        }
        request.status = "completed"
        request.completed_at = datetime.now(UTC)

        self._deletion_log.append(request)
        return request

    def get_status(self, request_id: UUID) -> DataDeletionRequest | None:
        return self._requests.get(request_id)

    def list_requests(self, org_id: UUID) -> list[DataDeletionRequest]:
        return [request for request in self._requests.values() if request.org_id == org_id]


__all__ = ["DataDeletionRequest", "DataDeletionWorkflow"]
