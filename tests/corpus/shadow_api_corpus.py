from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.api_inventory import ApiDocExposureStrategy, ApiInventoryStrategy
from storage.db.models import RawProbe


def _probe(*, request: dict[str, object], response: dict[str, object]) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        worker_id="corpus-shadow-api",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


def test_deprecated_api_v1_active() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://api.example.test/api/v1/users",
            "body": json.dumps(
                {
                    "probe_type": "deprecated_version",
                    "target_url": "https://api.example.test/api/v1/users",
                }
            ),
        },
        response={"status_code": 200, "content_type": "application/json", "body": '{"users":[]}'},
    )

    artifact = ApiInventoryStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "shadow_api"
    assert artifact.confidence_score == 0.87


def test_swagger_exposed() -> None:
    probe = _probe(
        request={"method": "GET", "url": "https://api.example.test/swagger.json"},
        response={
            "status_code": 200,
            "content_type": "application/json",
            "body": json.dumps(
                {
                    "swagger": "2.0",
                    "paths": {"/users": {"get": {}}},
                    "definitions": {"User": {"type": "object"}},
                }
            ),
        },
    )

    artifact = ApiDocExposureStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "api_doc_exposure"
    assert artifact.confidence_score == 0.93


def test_current_api_v2_404_no_finding() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://api.example.test/api/v2/",
            "body": json.dumps(
                {
                    "probe_type": "current_version",
                    "target_url": "https://api.example.test/api/v2/",
                }
            ),
        },
        response={"status_code": 404, "content_type": "application/json", "body": "{}"},
    )

    assert ApiInventoryStrategy().validate(probe, None) is None


def test_admin_endpoint_accessible() -> None:
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://api.example.test/admin",
            "body": json.dumps(
                {
                    "probe_type": "admin_endpoint",
                    "target_url": "https://api.example.test/admin",
                }
            ),
        },
        response={"status_code": 200, "content_type": "text/plain", "body": "admin console"},
    )

    artifact = ApiInventoryStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.proof_type == "shadow_api"
    assert artifact.confidence_score == 0.85
