from __future__ import annotations

import asyncio
import gzip
import json
import os
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from storage.db.models import ProofArtifact, RawProbe


class EvidenceStore:
    def __init__(self, s3_client: BaseClient | None = None, bucket_name: str | None = None) -> None:
        self._bucket_name = bucket_name or os.getenv("EVIDENCE_BUCKET")
        if not self._bucket_name:
            raise ValueError("EVIDENCE_BUCKET environment variable is required")

        if s3_client is not None:
            self._s3 = s3_client
            return

        aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        aws_session_token = os.getenv("AWS_SESSION_TOKEN")
        aws_region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        aws_endpoint_url = os.getenv("AWS_ENDPOINT_URL")

        client_kwargs: dict[str, object] = {
            "service_name": "s3",
            "region_name": aws_region,
        }
        if aws_access_key_id:
            client_kwargs["aws_access_key_id"] = aws_access_key_id
        if aws_secret_access_key:
            client_kwargs["aws_secret_access_key"] = aws_secret_access_key
        if aws_session_token:
            client_kwargs["aws_session_token"] = aws_session_token
        if aws_endpoint_url:
            client_kwargs["endpoint_url"] = aws_endpoint_url

        self._s3 = boto3.client(**client_kwargs)

    def write_probe(self, scan_id: UUID | str, finding_id: UUID | str, probe: RawProbe) -> str:
        probe_id = self._stringify(probe.id)
        key = f"{self._stringify(scan_id)}/{self._stringify(finding_id)}/{probe_id}.json.gz"
        payload = {
            "probe_id": probe_id,
            "attack_task_id": self._stringify(probe.attack_task_id),
            "worker_id": probe.worker_id,
            "timestamp": self._serialize_value(probe.timestamp),
            "request": self._serialize_value(probe.request),
            "response": self._serialize_value(probe.response),
            "control_probe_id": self._serialize_value(probe.control_probe_id),
        }
        self._put_gzip_json(key, payload)
        return key

    def write_artifact(self, scan_id: UUID | str, finding_id: UUID | str, artifact: ProofArtifact) -> str:
        artifact_id = self._stringify(artifact.id)
        key = f"{self._stringify(scan_id)}/{self._stringify(finding_id)}/proof_{artifact_id}.json.gz"
        payload = {
            "artifact_id": artifact_id,
            "attack_task_id": self._stringify(artifact.attack_task_id),
            "finding_id": self._serialize_value(artifact.finding_id),
            "proof_type": artifact.proof_type,
            "confidence_score": artifact.confidence_score,
            "attack_probe_id": self._stringify(artifact.attack_probe_id),
            "control_probe_id": self._serialize_value(artifact.control_probe_id),
            "identity_role": self._serialize_value(artifact.identity_role),
            "state_diff": self._serialize_value(artifact.state_diff),
            "summary": artifact.summary,
            "evidence_notes": artifact.evidence_notes,
        }
        self._put_gzip_json(key, payload)
        return key

    def read_probe(self, scan_id: UUID | str, finding_id: UUID | str, probe_id: UUID | str) -> dict[str, object]:
        key = f"{self._stringify(scan_id)}/{self._stringify(finding_id)}/{self._stringify(probe_id)}.json.gz"
        return self.read_json_object(key)

    def read_json_object(self, key: str) -> dict[str, Any]:
        response = self._s3.get_object(Bucket=self._bucket_name, Key=key)
        body = response["Body"].read()
        payload = json.loads(gzip.decompress(body).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"Evidence payload is not an object: {key}")
        return payload

    async def save_bundle(self, finding_id: UUID, bundle_data: dict[str, Any]) -> UUID:
        bundle_id = uuid4()
        key = self._bundle_key(finding_id)
        serialized_bundle = self._serialize_value(bundle_data)
        if not isinstance(serialized_bundle, dict):
            raise ValueError("Evidence bundle payload must be an object")
        payload = {
            **serialized_bundle,
            "bundle_id": str(bundle_id),
            "finding_id": str(finding_id),
            "created_at": datetime.now(UTC).isoformat(),
        }
        await asyncio.to_thread(self._put_gzip_json, key, payload)
        return bundle_id

    async def load_bundle(self, finding_id: UUID) -> dict[str, Any] | None:
        key = self._bundle_key(finding_id)
        try:
            return await asyncio.to_thread(self.read_json_object, key)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") in {"NoSuchKey", "404", "NotFound"}:
                return None
            raise

    def list_scan_objects(self, scan_id: UUID | str) -> list[dict[str, Any]]:
        prefix = f"{self._stringify(scan_id)}/"
        paginator = self._s3.get_paginator("list_objects_v2")
        records: list[dict[str, Any]] = []
        for page in paginator.paginate(Bucket=self._bucket_name, Prefix=prefix):
            contents = page.get("Contents", [])
            if not isinstance(contents, list):
                continue
            for item in contents:
                if not isinstance(item, dict):
                    continue
                key = item.get("Key")
                if not isinstance(key, str) or not key.endswith(".json.gz"):
                    continue
                records.append({"key": key, "payload": self.read_json_object(key)})
        return records

    def _put_gzip_json(self, key: str, payload: dict[str, object]) -> None:
        body = gzip.compress(json.dumps(payload, default=self._serialize_value, separators=(",", ":")).encode("utf-8"))
        self._s3.put_object(
            Bucket=self._bucket_name,
            Key=key,
            Body=body,
            ContentType="application/json",
            ContentEncoding="gzip",
        )

    def _bundle_key(self, finding_id: UUID) -> str:
        return f"bundles/{self._stringify(finding_id)}.json.gz"

    def _serialize_value(self, value: object) -> object:
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Decimal):
            return float(value)
        if isinstance(value, dict):
            return {str(key): self._serialize_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._serialize_value(item) for item in value]
        return value

    def _stringify(self, value: UUID | str | None) -> str:
        if value is None:
            raise ValueError("Expected non-null identifier")
        return str(value)
