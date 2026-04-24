from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

from storage.db.models import ProofArtifact, RawProbe
from storage.evidence.store import EvidenceStore


def _probe(*, attack_task_id=None) -> RawProbe:
    task_id = attack_task_id or uuid4()
    return RawProbe(
        id=uuid4(),
        attack_task_id=task_id,
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request={"method": "GET", "url": "https://example.test/api/users/1"},
        response={"status": 200, "body": {"ok": True}},
        control_probe_id=None,
    )


def _artifact(*, attack_task_id, attack_probe_id, control_probe_id) -> ProofArtifact:
    return ProofArtifact(
        id=uuid4(),
        attack_task_id=attack_task_id,
        proof_type="differential",
        confidence_score=0.90,
        attack_probe_id=attack_probe_id,
        control_probe_id=control_probe_id,
        summary="proof summary",
        evidence_notes="notes",
    )


def test_write_probe_uses_expected_key_pattern() -> None:
    s3_client = MagicMock()
    store = EvidenceStore(s3_client=s3_client, bucket_name="evidence-bucket")
    scan_id = uuid4()
    finding_id = uuid4()
    probe = _probe()

    key = store.write_probe(scan_id=scan_id, finding_id=finding_id, probe=probe)

    assert key == f"{scan_id}/{finding_id}/{probe.id}.json.gz"
    s3_client.put_object.assert_called_once()
    put_kwargs = s3_client.put_object.call_args.kwargs
    assert put_kwargs["Bucket"] == "evidence-bucket"
    assert put_kwargs["Key"] == key


def test_write_artifact_uses_expected_key_pattern() -> None:
    s3_client = MagicMock()
    store = EvidenceStore(s3_client=s3_client, bucket_name="evidence-bucket")
    scan_id = uuid4()
    finding_id = uuid4()
    probe = _probe()
    artifact = _artifact(
        attack_task_id=probe.attack_task_id,
        attack_probe_id=probe.id,
        control_probe_id=uuid4(),
    )

    key = store.write_artifact(scan_id=scan_id, finding_id=finding_id, artifact=artifact)

    assert key == f"{scan_id}/{finding_id}/proof_{artifact.id}.json.gz"
    s3_client.put_object.assert_called_once()
    put_kwargs = s3_client.put_object.call_args.kwargs
    assert put_kwargs["Bucket"] == "evidence-bucket"
    assert put_kwargs["Key"] == key


def test_write_payloads_are_gzip_compressed() -> None:
    s3_client = MagicMock()
    store = EvidenceStore(s3_client=s3_client, bucket_name="evidence-bucket")
    scan_id = uuid4()
    finding_id = uuid4()
    probe = _probe()

    store.write_probe(scan_id=scan_id, finding_id=finding_id, probe=probe)

    put_kwargs = s3_client.put_object.call_args.kwargs
    assert put_kwargs["ContentType"] == "application/json"
    assert put_kwargs["ContentEncoding"] == "gzip"
    assert isinstance(put_kwargs["Body"], bytes)
    assert put_kwargs["Body"][:2] == b"\x1f\x8b"

    decompressed = gzip.decompress(put_kwargs["Body"]).decode("utf-8")
    payload = json.loads(decompressed)
    assert payload["probe_id"] == str(probe.id)
    assert payload["attack_task_id"] == str(probe.attack_task_id)
