from __future__ import annotations

from typing import Any

from scripts.check_evidence_consistency import check_consistency


class _SeededEvidenceStore:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    def list_scan_objects(self, scan_id: str) -> list[dict[str, Any]]:
        prefix = f"{scan_id}/"
        return [record for record in self._records if str(record.get("key", "")).startswith(prefix)]


def test_orphaned_probe_appears_in_report() -> None:
    scan_id = "scan-1"
    store = _SeededEvidenceStore(
        [
            {
                "key": f"{scan_id}/finding-1/probe-orphan.json.gz",
                "payload": {"probe_id": "probe-orphan", "attack_task_id": "task-1"},
            }
        ]
    )

    report = check_consistency(scan_id=scan_id, store=store)  # type: ignore[arg-type]

    assert report.orphaned_probes == ["probe-orphan"]
    assert report.orphaned_proofs == []


def test_orphaned_proof_without_finding_is_detected() -> None:
    scan_id = "scan-1"
    store = _SeededEvidenceStore(
        [
            {
                "key": f"{scan_id}/finding-1/probe-1.json.gz",
                "payload": {"probe_id": "probe-1", "attack_task_id": "task-1"},
            },
            {
                "key": f"{scan_id}/finding-1/proof-proof-1.json.gz",
                "payload": {
                    "artifact_id": "proof-1",
                    "finding_id": "finding-1",
                    "attack_probe_id": "probe-1",
                },
            },
            {
                "key": f"{scan_id}/finding-missing/proof-proof-orphan.json.gz",
                "payload": {
                    "artifact_id": "proof-orphan",
                    "finding_id": "finding-missing",
                    "attack_probe_id": "probe-1",
                },
            },
            {
                "key": f"{scan_id}/reports/report.json.gz",
                "payload": {"findings": [{"id": "finding-1"}]},
            },
        ]
    )

    report = check_consistency(scan_id=scan_id, store=store)  # type: ignore[arg-type]

    assert report.orphaned_proofs == ["proof-orphan"]


def test_clean_evidence_data_returns_empty_report() -> None:
    scan_id = "scan-1"
    store = _SeededEvidenceStore(
        [
            {
                "key": f"{scan_id}/finding-1/probe-1.json.gz",
                "payload": {"probe_id": "probe-1", "attack_task_id": "task-1"},
            },
            {
                "key": f"{scan_id}/finding-1/proof-proof-1.json.gz",
                "payload": {
                    "artifact_id": "proof-1",
                    "finding_id": "finding-1",
                    "attack_probe_id": "probe-1",
                },
            },
            {
                "key": f"{scan_id}/reports/report.json.gz",
                "payload": {"findings": [{"id": "finding-1"}]},
            },
        ]
    )

    report = check_consistency(scan_id=scan_id, store=store)  # type: ignore[arg-type]

    assert report.orphaned_probes == []
    assert report.orphaned_proofs == []
    assert report.broken_report_links == []
