from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from control_plane.reporting import ReportingService
from storage.db.models import Endpoint, Finding, Scan, Severity, Target


async def _assemble_report_with_probe(
    probe_metadata: dict | None,
    validator_name: str | None = None,
) -> dict:
    scan_id = uuid4()
    target = Target(id=uuid4(), url="https://example.com", name="test", config={})
    scan = Scan(id=scan_id, target_id=target.id, status="complete")
    scan.target = target

    endpoint = Endpoint(
        id=uuid4(),
        asset_map_id=uuid4(),
        url_pattern="/api/data",
        method="GET",
        auth_required=True,
        parameters=[],
    )
    finding = Finding(
        id=uuid4(),
        scan_id=scan_id,
        title="Provider attribution check",
        description="desc",
        severity=Severity.high,
        attack_class="bola",
        affected_endpoint_id=endpoint.id,
        repro_steps="steps",
        fix_guidance="fix",
    )
    finding.extra_metadata = {}
    finding.affected_endpoint = endpoint
    finding.proof_artifacts = []
    finding.raw_probes = [SimpleNamespace(metadata=probe_metadata)] if probe_metadata is not None else []
    finding.proof_artifact = SimpleNamespace(validator_name=validator_name) if validator_name else None

    db = AsyncMock()
    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = scan
    findings_result = MagicMock()
    findings_result.scalars.return_value.all.return_value = [finding]
    db.execute = AsyncMock(side_effect=[scan_result, findings_result])

    service = ReportingService(db=db, evidence_store=None)
    return await service.assemble_report(scan_id)


@pytest.mark.asyncio
async def test_serialized_finding_contains_provider_attribution_key() -> None:
    report = await _assemble_report_with_probe(probe_metadata={})
    finding = report["findings"][0]
    assert "provider_attribution" in finding


@pytest.mark.asyncio
async def test_provider_engine_is_none_without_provider_id() -> None:
    report = await _assemble_report_with_probe(probe_metadata={})
    finding = report["findings"][0]
    assert finding["provider_attribution"]["engine"] is None


@pytest.mark.asyncio
async def test_provider_engine_is_set_from_probe_metadata() -> None:
    report = await _assemble_report_with_probe(probe_metadata={"provider_id": "hexstrike"})
    finding = report["findings"][0]
    assert finding["provider_attribution"]["engine"] == "hexstrike"


@pytest.mark.asyncio
async def test_serialized_finding_contains_validator_confirmation_key() -> None:
    report = await _assemble_report_with_probe(probe_metadata={"provider_id": "hexstrike"}, validator_name="strict-proof")
    finding = report["findings"][0]
    assert "validator_confirmation" in finding
    assert finding["validator_confirmation"]["strategy"] == "strict-proof"
