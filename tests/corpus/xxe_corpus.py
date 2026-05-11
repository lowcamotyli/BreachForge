from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from execution_plane.validator.strategies.xxe import XxeClassicStrategy, XxeErrorStrategy
from storage.db.models import RawProbe


def _probe(
    *,
    request: dict[str, object],
    response: dict[str, object],
    attack_task_id=None,
) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=attack_task_id or uuid4(),
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


@pytest.fixture
def mock_xxe_passwd_response() -> dict[str, object]:
    return {
        "status": 200,
        "body": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    }


def test_xxe_classic_corpus_hit(mock_xxe_passwd_response: dict[str, object]) -> None:
    strategy = XxeClassicStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml", "payload": "file:///etc/passwd"},
        response=mock_xxe_passwd_response,
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.95


def test_xxe_error_corpus_path() -> None:
    strategy = XxeErrorStrategy()
    attack_probe = _probe(
        request={"method": "POST", "url": "https://app.example.test/xml"},
        response={"status": 500, "body": "Error: /etc/passwd: Permission denied (SAXParser)"},
    )

    artifact = strategy.validate(attack_probe=attack_probe, control_probe=None)

    assert artifact is not None
    assert artifact.confidence_score >= 0.80
