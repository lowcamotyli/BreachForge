from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from execution_plane.validator.strategies.api_inventory import (
    ApiDocExposureStrategy,
    ApiInventoryStrategy,
    BackupFileExposureStrategy,
)
from storage.db.models import RawProbe


def _probe(*, request: dict[str, object], response: dict[str, object]) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


def test_deprecated_endpoint_200_json_returns_finding() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://example.test/api/v1/users",
            "body": json.dumps(
                {
                    "probe_type": "deprecated_version",
                    "target_url": "https://example.test/api/v1/users",
                }
            ),
        },
        response={"status_code": 200, "content_type": "application/json", "body": '{"users":[]}'},
    )

    artifact = ApiInventoryStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "shadow_api"
    assert artifact.confidence_score == pytest.approx(0.87)
    assert "probe_type=deprecated_version" in artifact.evidence_notes
    assert "has_json_body=True" in artifact.evidence_notes


def test_deprecated_endpoint_200_no_json_returns_finding() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://example.test/api/v1/users",
            "body": json.dumps({"probe_type": "deprecated_version"}),
        },
        response={"status_code": 200, "content_type": "text/plain", "body": "legacy endpoint active"},
    )

    artifact = ApiInventoryStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == pytest.approx(0.85)
    assert "has_json_body=False" in artifact.evidence_notes


def test_deprecated_endpoint_404_returns_none() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://example.test/api/v1/users",
            "body": json.dumps({"probe_type": "deprecated_version"}),
        },
        response={"status_code": 404, "content_type": "application/json", "body": "{}"},
    )

    assert ApiInventoryStrategy().validate(probe, None) is None


def test_deprecated_endpoint_410_returns_none() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://example.test/api/v1/users",
            "body": json.dumps({"probe_type": "deprecated_version"}),
        },
        response={"status_code": 410, "content_type": "application/json", "body": "{}"},
    )

    assert ApiInventoryStrategy().validate(probe, None) is None


def test_deprecated_endpoint_301_returns_none() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://example.test/api/v1/users",
            "body": json.dumps({"probe_type": "deprecated_version"}),
        },
        response={"status_code": 301, "content_type": "application/json", "body": ""},
    )

    assert ApiInventoryStrategy().validate(probe, None) is None


def test_swagger_spec_exposed() -> None:
    body = json.dumps(
        {
            "swagger": "2.0",
            "paths": {"/users": {"get": {}}},
            "definitions": {"User": {"type": "object"}},
        }
    )
    probe = _probe(
        request={"method": "GET", "url": "https://example.test/swagger.json"},
        response={"status_code": 200, "content_type": "application/json", "body": body},
    )

    artifact = ApiDocExposureStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "api_doc_exposure"
    assert artifact.confidence_score == pytest.approx(0.93)
    assert "spec_type=swagger" in artifact.evidence_notes
    assert "endpoint_count=1" in artifact.evidence_notes


def test_openapi_spec_exposed() -> None:
    body = json.dumps(
        {
            "openapi": "3.0.0",
            "paths": {"/users": {"get": {}}},
            "components": {"schemas": {"User": {"type": "object"}}},
        }
    )
    probe = _probe(
        request={"method": "GET", "url": "https://example.test/openapi.json"},
        response={"status_code": 200, "content_type": "application/json", "body": body},
    )

    artifact = ApiDocExposureStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == pytest.approx(0.93)
    assert "spec_type=openapi" in artifact.evidence_notes


def test_doc_exposure_200_no_signature() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://example.test/docs"},
        response={"status_code": 200, "content_type": "text/plain", "body": "Hello World"},
    )

    assert ApiDocExposureStrategy().validate(probe, None) is None


def test_doc_exposure_404() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://example.test/swagger.json"},
        response={"status_code": 404, "content_type": "application/json", "body": "{}"},
    )

    assert ApiDocExposureStrategy().validate(probe, None) is None


def test_backup_file_text_plain() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://example.test/config.bak"},
        response={"status_code": 200, "content_type": "text/plain", "body": "DB_PASSWORD=test"},
    )

    artifact = BackupFileExposureStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "backup_file_exposure"
    assert artifact.confidence_score == pytest.approx(0.90)
    assert "content_type=text/plain" in artifact.evidence_notes


def test_backup_file_application() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://example.test/archive.bak"},
        response={
            "status_code": 200,
            "content_type": "application/octet-stream",
            "body": "binary backup bytes",
        },
    )

    artifact = BackupFileExposureStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.confidence_score == pytest.approx(0.90)
    assert "content_type=application/octet-stream" in artifact.evidence_notes


def test_backup_file_html_returns_none() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://example.test/config.bak"},
        response={"status_code": 200, "content_type": "text/html", "body": "<html>not found</html>"},
    )

    assert BackupFileExposureStrategy().validate(probe, None) is None


def test_backup_file_javascript_returns_none() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://example.test/config.bak"},
        response={"status_code": 200, "content_type": "text/javascript", "body": "window.location='/'"},
    )

    assert BackupFileExposureStrategy().validate(probe, None) is None


def test_backup_file_404_returns_none() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://example.test/config.bak"},
        response={"status_code": 404, "content_type": "text/plain", "body": "not found"},
    )

    assert BackupFileExposureStrategy().validate(probe, None) is None


def test_backup_evidence_has_preview_not_full_body() -> None:
    body = "A" * 1000
    probe = _probe(
        request={"method": "GET", "url": "https://example.test/config.bak"},
        response={"status_code": 200, "content_type": "text/plain", "body": body},
    )

    artifact = BackupFileExposureStrategy().validate(probe, None)

    assert artifact is not None
    assert "preview_bytes=256" in artifact.evidence_notes
    assert body not in artifact.evidence_notes
