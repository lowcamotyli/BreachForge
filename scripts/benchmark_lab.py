"""Benchmark runner for the ProofScan benchmark lab."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path


SENSITIVE_KEYS = {"authorization", "password", "secret", "token"}


def load_ground_truth(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def finding_matches_ground_truth(finding: dict[str, object], vuln: dict[str, object]) -> bool:
    return finding.get("type") == vuln.get("type") and finding.get("endpoint") == vuln.get("endpoint")


def compute_metrics(
    vulnerabilities: list[dict[str, object]],
    findings: list[dict[str, object]],
) -> dict[str, int | float]:
    tp = sum(
        1
        for vuln in vulnerabilities
        if any(finding_matches_ground_truth(finding, vuln) for finding in findings)
    )
    fp = sum(
        1
        for finding in findings
        if not any(finding_matches_ground_truth(finding, vuln) for vuln in vulnerabilities)
    )
    fn = len(vulnerabilities) - tp
    coverage = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    return {
        "coverage": coverage,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "time_to_proof_avg": 0.0,
        "unsafe_block_count": 0,
        "findings_count": len(findings),
        "ground_truth_count": len(vulnerabilities),
    }


def redact_sensitive(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: redact_sensitive(child)
            for key, child in value.items()
            if str(key).lower() not in SENSITIVE_KEYS
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value


def build_quick_result(ground_truth: dict[str, object]) -> dict[str, object]:
    vulnerabilities = ground_truth.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("ground truth vulnerabilities must be a list")

    mock_findings: list[dict[str, object]] = []
    metrics = compute_metrics(vulnerabilities, mock_findings)
    return {
        "lab_version": ground_truth.get("lab_version", "unknown"),
        "mode": "quick",
        **metrics,
        "timestamp_utc": datetime.now(UTC).isoformat(),
    }


def build_full_result(ground_truth: dict[str, object]) -> dict[str, object]:
    vulnerabilities = ground_truth.get("vulnerabilities", [])
    ground_truth_count = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
    return {
        "lab_version": ground_truth.get("lab_version", "unknown"),
        "mode": "full",
        "coverage": 0.0,
        "tp": 0,
        "fp": 0,
        "fn": ground_truth_count,
        "time_to_proof_avg": 0.0,
        "unsafe_block_count": 0,
        "findings_count": 0,
        "ground_truth_count": ground_truth_count,
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "note": "Full scan integration not yet implemented - run against live lab manually",
    }


def write_result(result: dict[str, object], output_path: Path | None) -> None:
    redacted = redact_sensitive(result)
    rendered = json.dumps(redacted, indent=2)
    print(rendered)
    if output_path is not None:
        output_path.write_text(rendered + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the ProofScan benchmark lab.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--quick", action="store_true", help="Run mock benchmark mode without HTTP.")
    mode.add_argument("--full", action="store_true", help="Emit full benchmark placeholder output.")
    parser.add_argument("--output", type=Path, help="Write benchmark metrics JSON to this file.")
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=Path("tests/benchmark_lab/ground_truth.json"),
        help="Path to ground truth manifest.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ground_truth = load_ground_truth(args.ground_truth)
    result = build_quick_result(ground_truth) if args.quick else build_full_result(ground_truth)
    write_result(result, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
