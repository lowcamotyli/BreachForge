from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from storage.evidence.store import EvidenceStore


@dataclass(slots=True)
class EvidenceConsistencyReport:
    orphaned_probes: list[str] = field(default_factory=list)
    orphaned_proofs: list[str] = field(default_factory=list)
    broken_report_links: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _EvidenceRecord:
    key: str
    payload: dict[str, Any]


def check_consistency(scan_id: str, store: EvidenceStore) -> EvidenceConsistencyReport:
    records = _load_records(scan_id, store)
    probes = _probe_records(records)
    proofs = _proof_records(records)
    report_finding_ids = _report_finding_ids(records)
    store_finding_ids = _store_finding_ids(scan_id=scan_id, records=records)

    referenced_probe_ids = {
        probe_id
        for proof in proofs.values()
        for probe_id in (
            _string_or_none(proof.payload.get("attack_probe_id")),
            _string_or_none(proof.payload.get("control_probe_id")),
        )
        if probe_id is not None
    }

    orphaned_probes = sorted(probe_id for probe_id in probes if probe_id not in referenced_probe_ids)
    orphaned_proofs = sorted(
        artifact_id
        for artifact_id, proof in proofs.items()
        if _proof_is_orphaned(scan_id=scan_id, proof=proof, report_finding_ids=report_finding_ids)
    )
    broken_report_links = sorted(finding_id for finding_id in report_finding_ids if finding_id not in store_finding_ids)

    return EvidenceConsistencyReport(
        orphaned_probes=orphaned_probes,
        orphaned_proofs=orphaned_proofs,
        broken_report_links=broken_report_links,
    )


def _load_records(scan_id: str, store: EvidenceStore) -> list[_EvidenceRecord]:
    list_scan_objects = getattr(store, "list_scan_objects", None)
    if not callable(list_scan_objects):
        raise TypeError("EvidenceStore-compatible object must provide list_scan_objects(scan_id)")

    records: list[_EvidenceRecord] = []
    for item in list_scan_objects(scan_id):
        record = _normalize_record(item)
        if record is not None:
            records.append(record)
    return records


def _normalize_record(item: object) -> _EvidenceRecord | None:
    if isinstance(item, dict):
        key = item.get("key")
        payload = item.get("payload")
    else:
        key = getattr(item, "key", None)
        payload = getattr(item, "payload", None)

    if not isinstance(key, str):
        return None
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        return None
    return _EvidenceRecord(key=key, payload=payload)


def _probe_records(records: list[_EvidenceRecord]) -> dict[str, _EvidenceRecord]:
    probes: dict[str, _EvidenceRecord] = {}
    for record in records:
        probe_id = _string_or_none(record.payload.get("probe_id"))
        if probe_id is not None:
            probes[probe_id] = record
    return probes


def _proof_records(records: list[_EvidenceRecord]) -> dict[str, _EvidenceRecord]:
    proofs: dict[str, _EvidenceRecord] = {}
    for record in records:
        artifact_id = _string_or_none(record.payload.get("artifact_id"))
        if artifact_id is None and "/proof_" not in record.key:
            continue
        if artifact_id is None:
            artifact_id = Path(record.key).name.removeprefix("proof_").removesuffix(".json.gz")
        proofs[artifact_id] = record
    return proofs


def _report_finding_ids(records: list[_EvidenceRecord]) -> set[str]:
    finding_ids: set[str] = set()
    for record in records:
        findings = record.payload.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            finding_id = _string_or_none(finding.get("id") or finding.get("finding_id"))
            if finding_id is not None:
                finding_ids.add(finding_id)
    return finding_ids


def _store_finding_ids(*, scan_id: str, records: list[_EvidenceRecord]) -> set[str]:
    finding_ids: set[str] = set()
    for record in records:
        path_finding_id = _finding_id_from_key(scan_id=scan_id, key=record.key)
        if path_finding_id is not None and _is_evidence_payload(record.payload):
            finding_ids.add(path_finding_id)

        payload_type = _string_or_none(record.payload.get("type"))
        if payload_type == "finding":
            payload_finding_id = _string_or_none(record.payload.get("id") or record.payload.get("finding_id"))
            if payload_finding_id is not None:
                finding_ids.add(payload_finding_id)
    return finding_ids


def _proof_is_orphaned(
    *,
    scan_id: str,
    proof: _EvidenceRecord,
    report_finding_ids: set[str],
) -> bool:
    payload_finding_id = _string_or_none(proof.payload.get("finding_id"))
    path_finding_id = _finding_id_from_key(scan_id=scan_id, key=proof.key)
    finding_id = payload_finding_id or path_finding_id
    if finding_id is None:
        return True
    if payload_finding_id is not None and path_finding_id is not None and payload_finding_id != path_finding_id:
        return True
    return bool(report_finding_ids and finding_id not in report_finding_ids)


def _finding_id_from_key(*, scan_id: str, key: str) -> str | None:
    parts = key.split("/")
    if len(parts) < 3 or parts[0] != scan_id:
        return None
    finding_id = parts[1].strip()
    if not finding_id:
        return None
    return finding_id


def _is_evidence_payload(payload: dict[str, Any]) -> bool:
    return "probe_id" in payload or "artifact_id" in payload


def _string_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check scan evidence consistency.")
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)

    report = check_consistency(scan_id=args.scan_id, store=EvidenceStore())
    payload = json.dumps(asdict(report), indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(f"{payload}\n", encoding="utf-8")
        return 0

    sys.stdout.write(f"{payload}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
