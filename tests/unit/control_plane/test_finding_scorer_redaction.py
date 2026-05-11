from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

from storage.db.models import AttackTask, Endpoint, Finding, ProofArtifact, RawProbe, Severity


class _DbStub:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, value: object) -> None:
        self.added.append(value)


async def _score_test_finding(
    *,
    attack_class: str = "sensitive_exposure",
    confidence_score: float = 0.95,
    evidence_notes: str = "secret_type=API_KEY; secret_fingerprint=abc123",
    artifact_metadata: dict[str, object] | None = None,
    proof_threshold: float = 0.85,
) -> Finding:
    sys.modules.setdefault("storage.db.session", SimpleNamespace(AsyncSessionLocal=lambda: None))
    from control_plane.finding_scorer import FindingScorer

    endpoint = Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern="/api/account/42",
        method="get",
        auth_required=True,
        parameters=[],
        observed_content_type=None,
        example_response_code=200,
    )
    attack_task = AttackTask(
        id=uuid4(),
        scan_id=uuid4(),
        endpoint_id=endpoint.id,
        attack_class=attack_class,
        target_parameter="Authorization",
        hypothesis="leaks credentials",
        priority_score=0.9,
        prerequisites=None,
        step_order=1,
    )
    artifact = ProofArtifact(
        id=uuid4(),
        attack_task_id=attack_task.id,
        finding_id=None,
        proof_type="response_diff",
        confidence_score=confidence_score,
        attack_probe_id=uuid4(),
        control_probe_id=None,
        identity_role="attacker",
        state_diff=None,
        summary="Sensitive material is exposed in API response",
        evidence_notes=evidence_notes,
    )
    artifact.attack_task = attack_task
    if artifact_metadata is not None:
        artifact.metadata = artifact_metadata

    scorer = FindingScorer(db=_DbStub(), proof_threshold=proof_threshold)

    async def _no_duplicate(*, scan_id: object, fingerprint: tuple[str, str, str]) -> None:
        return None

    scorer._find_duplicate = _no_duplicate  # type: ignore[method-assign]
    finding = await scorer.score(artifact=artifact, endpoint=endpoint)
    assert finding is not None
    return finding


@pytest.mark.asyncio
async def test_finding_payload_does_not_include_raw_secret_from_evidence_notes() -> None:
    sys.modules.setdefault("storage.db.session", SimpleNamespace(AsyncSessionLocal=lambda: None))
    from control_plane.finding_scorer import FindingScorer

    fake_secret = "sk_live_FAKE_SUPER_SECRET_VALUE_123456789"
    endpoint = Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern="/api/account/42",
        method="get",
        auth_required=True,
        parameters=[],
        observed_content_type=None,
        example_response_code=200,
    )
    attack_task = AttackTask(
        id=uuid4(),
        scan_id=uuid4(),
        endpoint_id=endpoint.id,
        attack_class="sensitive_exposure",
        target_parameter="Authorization",
        hypothesis="leaks credentials",
        priority_score=0.9,
        prerequisites=None,
        step_order=1,
    )
    artifact = ProofArtifact(
        id=uuid4(),
        attack_task_id=attack_task.id,
        finding_id=None,
        proof_type="response_diff",
        confidence_score=0.95,
        attack_probe_id=uuid4(),
        control_probe_id=None,
        identity_role="attacker",
        state_diff=None,
        summary="Sensitive material is exposed in API response",
        evidence_notes=(
            "matches=credential; request_has_auth=true; "
            f"secret_type=API_KEY; secret_fingerprint=abc123; ttl_bucket=short; raw_value={fake_secret}"
        ),
    )
    artifact.attack_task = attack_task

    scorer = FindingScorer(db=_DbStub())

    async def _no_duplicate(*, scan_id: object, fingerprint: tuple[str, str, str]) -> None:
        return None

    scorer._find_duplicate = _no_duplicate  # type: ignore[method-assign]

    finding = await scorer.score(artifact=artifact, endpoint=endpoint)
    assert finding is not None

    scoring_output = scorer.score_output(artifact=artifact)
    payload = {
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "attack_class": finding.attack_class,
        "score_version": scoring_output["score_version"],
        "exploitability_score": scoring_output["exploitability_score"],
        "score_explanation": scoring_output["score_explanation"],
    }

    serialized_payload = json.dumps(payload, sort_keys=True)
    assert fake_secret not in serialized_payload
    assert fake_secret not in payload["description"]
    assert fake_secret not in payload["score_explanation"]


@pytest.mark.asyncio
async def test_secret_blast_radius_matrix_is_recorded_for_new_finding() -> None:
    sys.modules.setdefault("storage.db.session", SimpleNamespace(AsyncSessionLocal=lambda: None))
    from control_plane.finding_scorer import FindingScorer

    endpoint = Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern="/api/account/42",
        method="get",
        auth_required=True,
        parameters=[],
        observed_content_type=None,
        example_response_code=200,
    )
    attack_task = AttackTask(
        id=uuid4(),
        scan_id=uuid4(),
        endpoint_id=endpoint.id,
        attack_class="sensitive_exposure",
        target_parameter="Authorization",
        hypothesis='{"probe_type":"impact_secret_blast_radius"}',
        priority_score=0.9,
        prerequisites=None,
        step_order=1,
    )
    attack_probe = RawProbe(
        id=uuid4(),
        attack_task_id=attack_task.id,
        worker_id="test-worker",
        request={"url": "https://app.example.com/api/account/42", "method": "GET"},
        response={"status": 302, "headers": {"Content-Type": "application/json"}, "body": '{"ok":true}'},
    )
    artifact = ProofArtifact(
        id=uuid4(),
        attack_task_id=attack_task.id,
        finding_id=None,
        proof_type="absolute",
        confidence_score=0.95,
        attack_probe_id=uuid4(),
        control_probe_id=None,
        identity_role="attacker",
        state_diff=None,
        summary="Sensitive material is exposed in API response",
        evidence_notes="follow_up=true; impact_probe=impact_secret_blast_radius",
    )
    artifact.attack_task = attack_task
    artifact.attack_probe = attack_probe

    scorer = FindingScorer(db=_DbStub())

    async def _no_duplicate(*, scan_id: object, fingerprint: tuple[str, str, str]) -> None:
        return None

    scorer._find_duplicate = _no_duplicate  # type: ignore[method-assign]
    finding = await scorer.score(artifact=artifact, endpoint=endpoint)
    assert finding is not None

    metadata = getattr(finding, "metadata", None)
    assert isinstance(metadata, dict)
    matrix = metadata.get("secret_blast_radius_matrix")
    assert isinstance(matrix, list)
    assert len(matrix) == 1
    assert matrix[0] == {
        "endpoint": "https://app.example.com/api/account/42",
        "method": "GET",
        "status": 302,
        "content_type": "application/json",
        "response_size": len('{"ok":true}'.encode("utf-8")),
        "auth_accepted": True,
    }


@pytest.mark.asyncio
async def test_secret_blast_radius_matrix_appends_for_duplicate_finding_and_rejects_401() -> None:
    sys.modules.setdefault("storage.db.session", SimpleNamespace(AsyncSessionLocal=lambda: None))
    from control_plane.finding_scorer import FindingScorer

    endpoint = Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern="/api/admin",
        method="head",
        auth_required=True,
        parameters=[],
        observed_content_type=None,
        example_response_code=200,
    )
    attack_task = AttackTask(
        id=uuid4(),
        scan_id=uuid4(),
        endpoint_id=endpoint.id,
        attack_class="sensitive_exposure",
        target_parameter="Authorization",
        hypothesis='{"probe_type":"impact_secret_blast_radius"}',
        priority_score=0.9,
        prerequisites=None,
        step_order=1,
    )
    artifact = ProofArtifact(
        id=uuid4(),
        attack_task_id=attack_task.id,
        finding_id=None,
        proof_type="absolute",
        confidence_score=0.92,
        attack_probe_id=uuid4(),
        control_probe_id=None,
        identity_role="attacker",
        state_diff=None,
        summary="Sensitive material is exposed in API response",
        evidence_notes="probe_type=impact_secret_blast_radius",
    )
    artifact.attack_task = attack_task
    attack_probe = RawProbe(
        id=uuid4(),
        attack_task_id=attack_task.id,
        worker_id="test-worker",
        request={"url": "https://app.example.com/api/admin", "method": "HEAD"},
        response={"status": 401, "headers": {"Content-Type": "text/plain"}, "body": "err"},
    )
    artifact.attack_probe = attack_probe

    existing_finding = Finding(
        id=uuid4(),
        scan_id=attack_task.scan_id,
        title="Existing",
        description="Existing finding",
        severity=Severity.high,
        attack_class="sensitive_exposure",
        affected_endpoint_id=endpoint.id,
        repro_steps="step",
        fix_guidance="fix",
    )
    existing_finding.metadata = {"secret_blast_radius_matrix": [{"endpoint": "/seed"}]}

    scorer = FindingScorer(db=_DbStub())

    async def _duplicate(*, scan_id: object, fingerprint: tuple[str, str, str]) -> Finding:
        return existing_finding

    scorer._find_duplicate = _duplicate  # type: ignore[method-assign]
    finding = await scorer.score(artifact=artifact, endpoint=endpoint)
    assert finding is None

    metadata = getattr(existing_finding, "metadata", None)
    assert isinstance(metadata, dict)
    matrix = metadata.get("secret_blast_radius_matrix")
    assert isinstance(matrix, list)
    assert len(matrix) == 2
    assert matrix[1] == {
        "endpoint": "https://app.example.com/api/admin",
        "method": "HEAD",
        "status": 401,
        "content_type": "text/plain",
        "response_size": 3,
        "auth_accepted": False,
    }


@pytest.mark.asyncio
async def test_severity_upgrade_critical_with_correlator() -> None:
    finding = await _score_test_finding(
        artifact_metadata={"active_replay": True, "unauthenticated_exposure": True},
    )

    assert finding.severity is Severity.critical
    metadata = getattr(finding, "metadata", None)
    assert isinstance(metadata, dict)
    assert metadata["severity_factors"] == [
        {
            "source": "active_replay",
            "confidence": 0.95,
            "description": "Secret replay succeeded against the exposed target.",
        },
        {
            "source": "unauthenticated_exposure",
            "confidence": 0.95,
            "description": "The secret exposure is reachable without authentication.",
        },
    ]
    assert metadata["severity_explanation"] == (
        "Secret replay succeeded against the exposed target.; "
        "The secret exposure is reachable without authentication."
    )


@pytest.mark.asyncio
async def test_severity_upgrade_high_blast_radius() -> None:
    finding = await _score_test_finding(
        confidence_score=0.8,
        artifact_metadata={"active_replay": True, "blast_radius_score": 0.8},
        proof_threshold=0.0,
    )

    assert finding.severity is Severity.high
    metadata = getattr(finding, "metadata", None)
    assert isinstance(metadata, dict)
    assert metadata["severity_factors"] == [
        {
            "source": "active_replay",
            "confidence": 0.85,
            "description": "Secret replay succeeded against the exposed target.",
        },
        {
            "source": "blast_radius",
            "confidence": 0.85,
            "description": "Blast radius evidence shows broad downstream impact.",
        },
    ]


@pytest.mark.asyncio
async def test_noise_guard_no_upgrade_cors_alone() -> None:
    finding = await _score_test_finding(
        confidence_score=0.8,
        artifact_metadata={"cors_permissive": True},
        proof_threshold=0.0,
    )

    assert finding.severity is Severity.medium
    metadata = getattr(finding, "metadata", None)
    assert isinstance(metadata, dict)
    assert "severity_factors" not in metadata


@pytest.mark.asyncio
async def test_regression_non_secret_finding_unchanged() -> None:
    finding = await _score_test_finding(
        attack_class="workflow_abuse",
        confidence_score=0.9,
        evidence_notes="workflow transition accepted",
        artifact_metadata={"active_replay": True, "unauthenticated_exposure": True},
    )

    assert finding.severity is Severity.medium
    metadata = getattr(finding, "metadata", None)
    assert isinstance(metadata, dict)
    assert "severity_factors" not in metadata
