from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from execution_plane.validator.strategies.sensitive_exposure import SensitiveExposureStrategy
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


def test_sensitive_exposure_marks_impact_follow_up_proof() -> None:
    parent_finding_id = str(uuid4())
    probe = _probe(
        request={
            "method": "GET",
            "url": "https://example.test/config",
            "body": json.dumps(
                {
                    "probe_type": "impact_secret_classification",
                    "parent_finding_id": parent_finding_id,
                    "safe_mode": True,
                }
            ),
        },
        response={"status": 200, "body": '{"password":"supersecret123"}'},
    )

    artifact = SensitiveExposureStrategy().validate(probe, None)

    assert artifact is not None
    assert artifact.summary.startswith("Sensitive exposure impact proof")
    assert "follow_up=true" in artifact.evidence_notes
    assert "impact_probe=impact_secret_classification" in artifact.evidence_notes
    assert f"parent_finding_id={parent_finding_id}" in artifact.evidence_notes
    assert "safe_mode=true" in artifact.evidence_notes
