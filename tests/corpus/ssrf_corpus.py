from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.ssrf import SsrfStrategy
from storage.db.models import RawProbe


def test_mock_forwarding_endpoint_metadata_fixture_confirms_ssrf() -> None:
    task_id = uuid4()
    probe = RawProbe(
        id=uuid4(),
        attack_task_id=task_id,
        worker_id="corpus-ssrf",
        timestamp=datetime.now(UTC),
        request={
            "method": "GET",
            "url": "https://app.example.test/image?url=http://169.254.169.254/latest/meta-data/",
            "ssrf_target_url": "http://169.254.169.254/latest/meta-data/",
        },
        response={
            "status": 200,
            "body": "ami-id\nhostname\niam/security-credentials/example-role",
            "latency_ms": 120,
        },
    )

    artifact = SsrfStrategy().validate(attack_probe=probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score == 0.95
