from __future__ import annotations

import gzip
import json
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from botocore.exceptions import ClientError

from storage.db.models import EvidenceBundle
from storage.evidence.store import EvidenceStore


class _Body:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload


class _MemoryS3Client:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}

    def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: bytes,
        ContentType: str,
        ContentEncoding: str,
    ) -> None:
        assert ContentType == "application/json"
        assert ContentEncoding == "gzip"
        self.objects[(Bucket, Key)] = Body

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, _Body]:
        try:
            return {"Body": _Body(self.objects[(Bucket, Key)])}
        except KeyError as exc:
            raise ClientError(
                {"Error": {"Code": "NoSuchKey", "Message": "not found"}},
                "GetObject",
            ) from exc


def _bundle_data() -> dict[str, Any]:
    return {
        "request_chain": [
            {
                "method": "GET",
                "url": "https://example.test/api/users/1",
                "headers": {"Authorization": "<secret:0>"},
                "body": None,
                "response_status": 200,
                "response_body": {"id": 1},
            }
        ],
        "control_request": {
            "method": "GET",
            "url": "https://example.test/api/users/1",
            "headers": {},
            "body": None,
        },
        "attack_request": {
            "method": "GET",
            "url": "https://example.test/api/users/2",
            "headers": {"Authorization": "<secret:0>"},
            "body": None,
        },
        "state_diff": {"user.id": {"before": 1, "after": 2}},
        "identity_context": {"user_id": "user-1", "session_id": "session-1", "auth_method": "cookie"},
        "redacted_secrets_map": {"<secret:0>": {"path": "request_chain.0.headers.Authorization"}},
    }


def test_evidence_bundle_model_has_required_fields() -> None:
    mapper = sa.inspect(EvidenceBundle)
    columns = {column.key for column in mapper.mapper.column_attrs}

    assert {
        "id",
        "finding_id",
        "request_chain",
        "control_request",
        "attack_request",
        "state_diff",
        "identity_context",
        "redacted_secrets_map",
        "created_at",
    }.issubset(columns)


@pytest.mark.asyncio
async def test_save_bundle_returns_uuid() -> None:
    store = EvidenceStore(s3_client=_MemoryS3Client(), bucket_name="evidence-bucket")

    bundle_id = await store.save_bundle(finding_id=uuid4(), bundle_data=_bundle_data())

    assert isinstance(bundle_id, UUID)


@pytest.mark.asyncio
async def test_load_bundle_returns_none_for_missing_id() -> None:
    store = EvidenceStore(s3_client=_MemoryS3Client(), bucket_name="evidence-bucket")

    loaded = await store.load_bundle(finding_id=uuid4())

    assert loaded is None


@pytest.mark.asyncio
async def test_save_and_load_bundle_round_trip_data_integrity() -> None:
    s3_client = _MemoryS3Client()
    store = EvidenceStore(s3_client=s3_client, bucket_name="evidence-bucket")
    finding_id = uuid4()
    bundle_data = _bundle_data()

    bundle_id = await store.save_bundle(finding_id=finding_id, bundle_data=bundle_data)
    loaded = await store.load_bundle(finding_id=finding_id)

    assert loaded is not None
    assert loaded["bundle_id"] == str(bundle_id)
    assert loaded["finding_id"] == str(finding_id)
    for key, value in bundle_data.items():
        assert loaded[key] == value

    stored_body = s3_client.objects[("evidence-bucket", f"bundles/{finding_id}.json.gz")]
    decoded = json.loads(gzip.decompress(stored_body).decode("utf-8"))
    assert decoded == loaded
