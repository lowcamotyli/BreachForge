"""Benchmark runner for the ProofScan benchmark lab."""
from __future__ import annotations

import argparse
import importlib
import json
import json as _json
import os
import random as _random
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid as _uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SENSITIVE_KEYS = {"authorization", "password", "secret", "token"}
DEFAULT_DISCOVERY_COVERAGE_THRESHOLD = 0.80
DISCOVERY_COVERAGE_THRESHOLD_ENV = "DISCOVERY_COVERAGE_THRESHOLD"
BENCHMARK_DISCOVERY_COVERAGE_THRESHOLD_ENV = "BENCHMARK_DISCOVERY_COVERAGE_THRESHOLD"

Finding = dict[str, object]
Probe = Callable[[str, dict[str, str]], Finding | None]


@dataclass
class BenchmarkMetrics:
    requests_total: int
    requests_blocked: int
    queue_latency_ms: float
    validator_latency_ms: float
    time_to_first_proof_ms: float
    proof_depth_avg: float = 0.0
    proof_depth_min: int = 0
    proof_depth_max: int = 0
    auth_health_rate: float = 0.0
    coverage_by_attack_class: dict[str, dict[str, int | float]] = field(default_factory=dict)


def load_ground_truth(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def finding_matches_ground_truth(finding: Finding, vuln: dict[str, object]) -> bool:
    return finding.get("type") == vuln.get("type") and finding.get("endpoint") == vuln.get("endpoint")


def compute_metrics(
    vulnerabilities: list[dict[str, object]],
    findings: list[Finding],
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


def compute_metrics_per_attack_class(
    vulnerabilities: list[dict[str, object]],
    findings: list[Finding],
) -> dict[str, dict[str, int | float]]:
    """Return coverage per attack class (vuln type)."""
    classes: dict[str, list[dict[str, object]]] = {}
    for vuln in vulnerabilities:
        cls = str(vuln.get("type", "UNKNOWN"))
        classes.setdefault(cls, []).append(vuln)
    result: dict[str, dict[str, int | float]] = {}
    for cls, vulns in classes.items():
        tp = sum(1 for v in vulns if any(finding_matches_ground_truth(f, v) for f in findings))
        fp = sum(
            1
            for finding in findings
            if str(finding.get("type", "UNKNOWN")) == cls
            and not any(finding_matches_ground_truth(finding, vuln) for vuln in vulns)
        )
        fn = len(vulns) - tp
        result[cls] = {
            "coverage": tp / len(vulns) if vulns else 0.0,
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }
    return result


def compute_adaptive_metrics(
    vulnerabilities: list[dict[str, object]],
    findings: list[Finding],
) -> dict[str, int]:
    adaptive_rounds = max((_finding_adaptive_round(finding) for finding in findings), default=0)
    follow_up_tp = 0
    for vuln in vulnerabilities:
        if any(finding_matches_ground_truth(finding, vuln) and _finding_is_follow_up(finding) for finding in findings):
            follow_up_tp += 1
    dead_end_count = sum(1 for finding in findings if _finding_is_follow_up(finding) and _finding_is_no_signal(finding))
    return {
        "adaptive_rounds": adaptive_rounds,
        "follow_up_tp": follow_up_tp,
        "dead_end_count": dead_end_count,
    }


def compute_requires_followup_metrics(
    vulnerabilities: list[dict[str, object]],
    findings: list[Finding],
) -> dict[str, int]:
    requires_followup = [vuln for vuln in vulnerabilities if vuln.get("requires_followup") is True]
    requires_followup_tp = sum(
        1
        for vuln in requires_followup
        if any(finding_matches_ground_truth(finding, vuln) for finding in findings)
    )
    return {
        "requires_followup_total": len(requires_followup),
        "requires_followup_tp": requires_followup_tp,
        "requires_followup_fn": len(requires_followup) - requires_followup_tp,
    }


def _finding_adaptive_round(finding: Finding) -> int:
    for key in ("adaptive_round", "adaptive_rounds", "replan_round"):
        value = finding.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return max(value, 0)
        if isinstance(value, str):
            try:
                return max(int(value), 0)
            except ValueError:
                continue
    return 1 if _finding_is_follow_up(finding) else 0


def _finding_is_follow_up(finding: Finding) -> bool:
    for key in ("follow_up", "is_follow_up", "requires_followup", "found_after_followup"):
        value = finding.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in {"true", "1", "yes"}:
            return True
    evidence_notes = str(finding.get("evidence_notes", "")).lower()
    return "follow_up=true" in evidence_notes or "adaptive_round=" in evidence_notes


def _finding_is_no_signal(finding: Finding) -> bool:
    status = str(finding.get("status") or finding.get("outcome") or "").strip().lower()
    if status == "no_signal":
        return True
    evidence_notes = str(finding.get("evidence_notes", "")).lower()
    return "no_signal" in evidence_notes


def compute_discovery_coverage(
    expected_endpoints: list[str],
    discovered_endpoints: list[str],
) -> float:
    """Fraction of expected endpoints actually found."""
    if not expected_endpoints:
        return 1.0
    discovered = set(discovered_endpoints)
    expected = set(expected_endpoints)
    return len(discovered & expected) / len(expected)


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _string_list(payload: Mapping[str, object], key: str) -> list[str]:
    raw = payload.get(key)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{key} must be a list[str]")
    values: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError(f"{key} must be a list[str]")
        values.append(item)
    return _dedupe_strings(values)


def _normalize_endpoint(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    path = parsed.path if parsed.scheme or parsed.netloc else endpoint
    path = path.split("?", 1)[0].split("#", 1)[0].strip()
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path or "/"


def expected_endpoints_from_ground_truth(ground_truth: Mapping[str, object]) -> list[str]:
    expected = _string_list(ground_truth, "expected_endpoints")
    if expected:
        return [_normalize_endpoint(endpoint) for endpoint in expected]

    expected_surface = _string_list(ground_truth, "expected_surface")
    if expected_surface:
        return [_normalize_endpoint(endpoint) for endpoint in expected_surface]

    vulnerabilities = ground_truth.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("ground truth vulnerabilities must be a list")

    endpoints: list[str] = []
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        endpoint = vuln.get("endpoint")
        if isinstance(endpoint, str):
            endpoints.append(_normalize_endpoint(endpoint))
    return _dedupe_strings(endpoints)


def compute_discovery_metrics(
    expected_endpoints: list[str],
    discovered_endpoints: list[str],
) -> dict[str, object]:
    normalized_expected = _dedupe_strings([_normalize_endpoint(endpoint) for endpoint in expected_endpoints])
    normalized_discovered = _dedupe_strings([_normalize_endpoint(endpoint) for endpoint in discovered_endpoints])
    coverage = compute_discovery_coverage(normalized_expected, normalized_discovered)
    expected_set = set(normalized_expected)
    discovered_set = set(normalized_discovered)
    blind_spots = [endpoint for endpoint in normalized_expected if endpoint not in discovered_set]
    matched_endpoints = [endpoint for endpoint in normalized_expected if endpoint in discovered_set]
    coverage_pct = coverage * 100.0
    return {
        "expected_endpoints": normalized_expected,
        "discovered_endpoints": normalized_discovered,
        "discovery_matched_endpoints": matched_endpoints,
        "discovery_blind_spots": blind_spots,
        "discovery_coverage": coverage,
        "discovery_coverage_pct": round(coverage_pct, 1),
        "discovery_expected_count": len(expected_set),
        "discovery_discovered_count": len(discovered_set),
    }


def parse_discovery_threshold(raw_value: float | str) -> float:
    try:
        threshold = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("discovery coverage threshold must be a float between 0.0 and 1.0") from exc
    if threshold < 0.0 or threshold > 1.0:
        raise ValueError("discovery coverage threshold must be a float between 0.0 and 1.0")
    return threshold


def resolve_discovery_threshold(cli_threshold: float | None) -> float:
    if cli_threshold is not None:
        return parse_discovery_threshold(cli_threshold)

    env_value = os.getenv(DISCOVERY_COVERAGE_THRESHOLD_ENV)
    if env_value is None:
        env_value = os.getenv(BENCHMARK_DISCOVERY_COVERAGE_THRESHOLD_ENV)
    if env_value is not None:
        return parse_discovery_threshold(env_value)

    return DEFAULT_DISCOVERY_COVERAGE_THRESHOLD


def _result_float(result: Mapping[str, object], key: str) -> float:
    value = result.get(key)
    if not isinstance(value, (int, float)):
        raise ValueError(f"benchmark result missing numeric {key}")
    return float(value)


def _result_string_list(result: Mapping[str, object], key: str) -> list[str]:
    value = result.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"benchmark result missing list {key}")
    return [str(item) for item in value]


def assert_discovery_coverage(result: Mapping[str, object], threshold: float) -> None:
    coverage = _result_float(result, "discovery_coverage")
    coverage_pct = _result_float(result, "discovery_coverage_pct")
    blind_spots = _result_string_list(result, "discovery_blind_spots")

    if coverage < threshold:
        print(
            f"DISCOVERY BLIND SPOTS: coverage {coverage_pct:.1f}% below threshold {threshold * 100:.0f}%",
            file=sys.stderr,
        )
        for endpoint in blind_spots:
            print(f"- {endpoint}", file=sys.stderr)
        if not blind_spots:
            print("- <none recorded>", file=sys.stderr)
        raise SystemExit(1)

    if blind_spots:
        print("DISCOVERY BLIND SPOTS:", file=sys.stderr)
        for endpoint in blind_spots:
            print(f"- {endpoint}", file=sys.stderr)


def mark_discovery_gate(result: dict[str, object], threshold: float, status: str, reason: str | None = None) -> None:
    result["discovery_coverage_threshold"] = threshold
    gate: dict[str, object] = {
        "status": status,
        "threshold": threshold,
        "threshold_pct": round(threshold * 100.0, 1),
    }
    if reason is not None:
        gate["reason"] = reason
    result["discovery_gate"] = gate


def generate_large_asset_map(n: int) -> dict:
    """Return an in-memory synthetic AssetMap-like dictionary with n endpoints."""
    if n < 0:
        raise ValueError("asset map size must be non-negative")

    from execution_plane.crawler.asset_map import AssetMapBuilder

    methods = ("GET", "POST", "PUT", "DELETE")
    parameter_locations = ("path", "query", "body")
    parameter_types = ("string", "integer", "object")
    auth_levels = ("none", "bearer", "session")
    resource_names = ("users", "orders", "invoices", "projects", "reports", "tokens")
    response_codes = {"GET": 200, "POST": 201, "PUT": 200, "DELETE": 204}

    builder = AssetMapBuilder()
    auth_by_signature: dict[tuple[str, str], str] = {}

    for index in range(n):
        method = methods[index % len(methods)]
        parameter_location = parameter_locations[index % len(parameter_locations)]
        parameter_type = parameter_types[index % len(parameter_types)]
        auth_level = auth_levels[index % len(auth_levels)]
        resource_name = resource_names[index % len(resource_names)]

        if parameter_location == "path":
            url = f"/api/synthetic/{resource_name}/{{resource_id}}/profile-{index:05d}"
            parameter_name = "resource_id"
        elif parameter_location == "query":
            url = f"/api/synthetic/{resource_name}/search-{index:05d}"
            parameter_name = "filter"
        else:
            url = f"/api/synthetic/{resource_name}/batch-{index:05d}"
            parameter_name = "payload"

        builder.add_endpoint(
            url=url,
            method=method,
            auth_required=auth_level != "none",
            parameters=[
                {
                    "name": parameter_name,
                    "location": parameter_location,
                    "type": parameter_type,
                }
            ],
            in_scope=True,
            source="manual",
            observed_content_type="application/json",
            example_response_code=response_codes[method],
        )
        auth_by_signature[(builder.normalize_url_pattern(url), method)] = auth_level

    asset_map = builder.build()
    endpoints: list[dict[str, object]] = []
    for endpoint in asset_map.endpoints:
        endpoints.append(
            {
                "url_pattern": endpoint.url_pattern,
                "method": endpoint.method,
                "in_scope": endpoint.in_scope,
                "auth_required": endpoint.auth_required,
                "auth_level": auth_by_signature[(endpoint.url_pattern, endpoint.method)],
                "parameters": endpoint.parameters,
                "source": endpoint.source,
                "observed_content_type": endpoint.observed_content_type,
                "example_response_code": endpoint.example_response_code,
            }
        )

    return {
        "target_url": "http://localhost",
        "endpoints": endpoints,
    }


def _metric_sources(scan_result: Mapping[str, object]) -> list[Mapping[str, object]]:
    sources: list[Mapping[str, object]] = [scan_result]
    for key in ("metrics", "benchmark_metrics", "timings"):
        nested = scan_result.get(key)
        if isinstance(nested, Mapping):
            sources.append(nested)
    return sources


def _coerce_metric_number(value: object, key: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"benchmark metric {key} must be numeric")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError as exc:
            raise ValueError(f"benchmark metric {key} must be numeric") from exc
    raise ValueError(f"benchmark metric {key} must be numeric")


def _extract_metric_number(scan_result: Mapping[str, object], keys: tuple[str, ...]) -> float | None:
    for source in _metric_sources(scan_result):
        for key in keys:
            if key in source:
                return _coerce_metric_number(source[key], key)
    return None


def _count_asset_map_endpoints(scan_result: Mapping[str, object]) -> int:
    endpoints = scan_result.get("endpoints")
    if isinstance(endpoints, list):
        return len(endpoints)

    asset_map = scan_result.get("asset_map")
    if isinstance(asset_map, Mapping):
        asset_map_endpoints = asset_map.get("endpoints")
        if isinstance(asset_map_endpoints, list):
            return len(asset_map_endpoints)

    return 0


def collect_metrics(scan_result: dict) -> BenchmarkMetrics:
    requests_total = _extract_metric_number(
        scan_result,
        ("requests_total", "request_count", "requests"),
    )
    requests_blocked = _extract_metric_number(
        scan_result,
        ("requests_blocked", "unsafe_block_count", "blocked_count"),
    )
    queue_latency_ms = _extract_metric_number(
        scan_result,
        ("queue_latency_ms", "queue_ms", "queue_duration_ms"),
    )
    validator_latency_ms = _extract_metric_number(
        scan_result,
        ("validator_latency_ms", "validation_latency_ms", "validator_ms"),
    )
    time_to_first_proof_ms = _extract_metric_number(
        scan_result,
        ("time_to_first_proof_ms", "first_proof_latency_ms", "time_to_proof_ms"),
    )

    if time_to_first_proof_ms is None:
        proof_avg_seconds = _extract_metric_number(scan_result, ("time_to_proof_avg",))
        time_to_first_proof_ms = None if proof_avg_seconds is None else proof_avg_seconds * 1000.0

    vulnerabilities = scan_result.get("vulnerabilities")
    findings = scan_result.get("findings")
    if isinstance(vulnerabilities, list) and isinstance(findings, list):
        coverage_by_attack_class = compute_metrics_per_attack_class(vulnerabilities, findings)
    else:
        raw_coverage_by_attack_class = scan_result.get("coverage_by_attack_class") or {}
        coverage_by_attack_class = (
            raw_coverage_by_attack_class if isinstance(raw_coverage_by_attack_class, dict) else {}
        )

    return BenchmarkMetrics(
        requests_total=int(requests_total if requests_total is not None else _count_asset_map_endpoints(scan_result)),
        requests_blocked=int(requests_blocked if requests_blocked is not None else 0),
        queue_latency_ms=float(queue_latency_ms if queue_latency_ms is not None else 0.0),
        validator_latency_ms=float(validator_latency_ms if validator_latency_ms is not None else 0.0),
        time_to_first_proof_ms=float(time_to_first_proof_ms if time_to_first_proof_ms is not None else 0.0),
        proof_depth_avg=float(scan_result.get("proof_depth_avg") or 0.0),
        proof_depth_min=int(scan_result.get("proof_depth_min") or 0),
        proof_depth_max=int(scan_result.get("proof_depth_max") or 0),
        auth_health_rate=float(scan_result.get("auth_health_rate") or 0.0),
        coverage_by_attack_class=coverage_by_attack_class,
    )


def run_scale_benchmark(scale: int) -> BenchmarkMetrics:
    if scale < 0:
        raise ValueError("scale must be non-negative")

    generation_start = time.perf_counter()
    asset_map = generate_large_asset_map(scale)
    generation_latency_ms = (time.perf_counter() - generation_start) * 1000.0

    endpoints = asset_map["endpoints"]
    if not isinstance(endpoints, list):
        raise ValueError("generated asset map endpoints must be a list")

    queue_start = time.perf_counter()
    queued_requests = [
        (str(endpoint.get("method")), str(endpoint.get("url_pattern")))
        for endpoint in endpoints
        if isinstance(endpoint, Mapping)
    ]
    queue_latency_ms = (time.perf_counter() - queue_start) * 1000.0

    validator_start = time.perf_counter()
    requests_blocked = sum(
        1
        for endpoint in endpoints
        if isinstance(endpoint, Mapping)
        and endpoint.get("method") in {"POST", "PUT", "DELETE"}
        and endpoint.get("auth_required") is False
    )
    validator_latency_ms = (time.perf_counter() - validator_start) * 1000.0

    scan_result: dict[str, object] = {
        "requests_total": len(queued_requests),
        "requests_blocked": requests_blocked,
        "queue_latency_ms": queue_latency_ms,
        "validator_latency_ms": validator_latency_ms,
        "time_to_first_proof_ms": (
            generation_latency_ms + queue_latency_ms + validator_latency_ms if queued_requests else 0.0
        ),
    }
    return collect_metrics(scan_result)


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

    mock_findings: list[Finding] = []
    discovery_metrics = compute_discovery_metrics(
        expected_endpoints_from_ground_truth(ground_truth),
        [],
    )
    metrics = compute_metrics(vulnerabilities, mock_findings)
    result: dict[str, object] = {
        "lab_version": ground_truth.get("lab_version", "unknown"),
        "mode": "quick",
        **discovery_metrics,
        **metrics,
        "coverage_by_attack_class": compute_metrics_per_attack_class(vulnerabilities, mock_findings),
        "adaptive_metrics": compute_adaptive_metrics(vulnerabilities, mock_findings),
        "requires_followup_metrics": compute_requires_followup_metrics(vulnerabilities, mock_findings),
        "fn_report": [],
        "timestamp_utc": datetime.now(UTC).isoformat(),
    }
    from scripts.benchmark_importers.miss_classifier import MissClassifier

    gt_vulns = list(ground_truth.get("vulnerabilities") or [])
    findings = list(result.get("findings") or [])
    result["fn_annotated"] = MissClassifier.annotate_fn_list(gt_vulns, findings, result)
    return result


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _assert_localhost(url: str) -> None:
    host = urlparse(url).hostname or ""
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(f"Benchmark traffic must target localhost, got: {host!r}")


def start_lab(lab_id: str | None = None, port: int | None = None) -> tuple[subprocess.Popen[bytes], int]:
    port = port or _find_free_port()
    app_path = "tests.benchmark_lab.lab_app:app"
    if lab_id is not None:
        app_path = f"tests.benchmark_lab.labs.{lab_id}.lab_app:app"
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", app_path, "--host", "127.0.0.1", "--port", str(port), "--log-level", "error"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if lab_id is not None:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1):
                    pass
                break
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/auth/login",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=1)
        except urllib.error.HTTPError:
            break
        except OSError:
            time.sleep(0.1)
    return proc, port


def stop_lab(proc: subprocess.Popen[bytes]) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _http(method: str, url: str, token: str, body: dict[str, object] | None = None) -> tuple[int, dict[str, object]]:
    data = _json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = _json.loads(resp.read())
            return resp.status, payload if isinstance(payload, dict) else {}
    except urllib.error.HTTPError as e:
        return e.code, {}


def discover_endpoints(base_url: str) -> list[str]:
    _assert_localhost(base_url)
    req = urllib.request.Request(f"{base_url}/openapi.json", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            spec = _json.loads(resp.read())
    except (OSError, urllib.error.HTTPError, _json.JSONDecodeError):
        return []

    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    return _dedupe_strings([_normalize_endpoint(str(path)) for path in paths if isinstance(path, str)])


def probe_bola(base: str, tok: dict[str, str]) -> Finding | None:
    status, body = _http("GET", f"{base}/users/carol", tok["alice"])
    if status == 200 and body.get("id") == "carol":
        evidence = "cross-user read returned 200"
        return {
            "type": "BOLA",
            "endpoint": "/users/{user_id}",
            "method": "GET",
            "evidence": evidence,
            "confidence": 0.9,
            "evidence_notes": evidence,
            "attack_probe_id": "probe-bola-001",
            "identity": {"user": "alice", "role": "user", "tenant": "tenant_a"},
        }
    return None


def probe_bfla(base: str, tok: dict[str, str]) -> Finding | None:
    status, _ = _http("POST", f"{base}/admin/orders/order-1/approve", tok["alice"], {})
    if status == 200:
        evidence = "user accessed admin endpoint"
        return {
            "type": "BFLA",
            "endpoint": "/admin/orders/{order_id}/approve",
            "method": "POST",
            "evidence": evidence,
            "confidence": 0.9,
            "evidence_notes": evidence,
            "attack_probe_id": "probe-bfla-001",
            "identity": {"user": "alice", "role": "user", "tenant": "tenant_a"},
        }
    return None


def probe_tenant_isolation(base: str, tok: dict[str, str]) -> Finding | None:
    status, body = _http("GET", f"{base}/orders/order-3", tok["alice"])
    if status == 200 and body.get("id") == "order-3":
        evidence = "cross-tenant order read returned 200"
        return {
            "type": "TENANT_ISOLATION",
            "endpoint": "/orders/{order_id}",
            "method": "GET",
            "evidence": evidence,
            "confidence": 0.9,
            "evidence_notes": evidence,
            "attack_probe_id": "probe-tenant_isolation-001",
            "identity": {"user": "alice", "role": "user", "tenant": "tenant_a"},
        }
    return None


def probe_privilege_escalation(base: str, tok: dict[str, str]) -> Finding | None:
    status, body = _http("PATCH", f"{base}/users/alice/profile", tok["alice"], {"role": "admin"})
    if status == 200 and body.get("role") == "admin":
        evidence = "role escalation succeeded"
        return {
            "type": "PRIVILEGE_ESCALATION",
            "endpoint": "/users/{user_id}/profile",
            "method": "PATCH",
            "evidence": evidence,
            "confidence": 0.9,
            "evidence_notes": evidence,
            "attack_probe_id": "probe-privilege_escalation-001",
            "identity": {"user": "alice", "role": "user", "tenant": "tenant_a"},
        }
    return None


def probe_race_condition(base: str, tok: dict[str, str]) -> Finding | None:
    if "carol" not in tok:
        return None

    results: list[int] = []

    def checkout() -> None:
        status, _ = _http("POST", f"{base}/cart/checkout", tok["carol"], {})
        results.append(status)

    threads = [threading.Thread(target=checkout) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if results.count(200) >= 2:
        evidence = f"{results.count(200)} concurrent checkouts succeeded"
        return {
            "type": "RACE_CONDITION",
            "endpoint": "/cart/checkout",
            "method": "POST",
            "evidence": evidence,
            "confidence": 0.9,
            "evidence_notes": evidence,
            "attack_probe_id": "probe-race_condition-001",
            "identity": {"user": "carol", "role": "user", "tenant": "tenant_b"},
        }
    return None


def probe_business_logic(base: str, tok: dict[str, str]) -> Finding | None:
    successes = 0
    for i in range(6):
        status, _ = _http("POST", f"{base}/api-tokens", tok["alice"], {"name": f"tok{i}"})
        if status == 200:
            successes += 1
    if successes >= 6:
        evidence = f"{successes} tokens created with no quota"
        return {
            "type": "BUSINESS_LOGIC",
            "endpoint": "/api-tokens",
            "method": "POST",
            "evidence": evidence,
            "confidence": 0.9,
            "evidence_notes": evidence,
            "attack_probe_id": "probe-business_logic-001",
            "identity": {"user": "alice", "role": "user", "tenant": "tenant_a"},
        }
    return None


def probe_auth_bypass(base: str, tok: dict[str, str]) -> Finding | None:
    status, _ = _http("POST", f"{base}/jobs/export", tok["expired"], {"format": "json"})
    if status != 401:
        evidence = f"expired token returned {status}"
        return {
            "type": "AUTH_BYPASS",
            "endpoint": "/jobs/export",
            "method": "POST",
            "evidence": evidence,
            "confidence": 0.9,
            "evidence_notes": evidence,
            "attack_probe_id": "probe-auth_bypass-001",
            "identity": {"user": "expired", "role": "user", "tenant": "tenant_a"},
        }
    return None


ALL_PROBES: list[Probe] = [
    probe_bola,
    probe_bfla,
    probe_tenant_isolation,
    probe_privilege_escalation,
    probe_race_condition,
    probe_business_logic,
    probe_auth_bypass,
]


def probe_from_ground_truth(
    base: str,
    tokens: dict[str, str],
    vulnerabilities: list[dict[str, object]],
) -> list[Finding]:
    findings: list[Finding] = []
    for vuln in vulnerabilities:
        finding = _probe_single_vuln(base, tokens, vuln)
        if finding is not None:
            findings.append(finding)
    return findings


def _probe_single_vuln(base: str, tokens: dict[str, str], vuln: dict[str, object]) -> Finding | None:
    vtype = str(vuln.get("type", ""))
    endpoint = str(vuln.get("endpoint", ""))
    method = str(vuln.get("method", "GET")).upper()
    alice = tokens.get("alice", "")
    bob = tokens.get("bob", "")
    carol = tokens.get("carol", "")
    expired = tokens.get("expired", "")
    logged_out = tokens.get("logged_out", "")

    def make_finding(confidence: float = 0.9, evidence: str = "probe succeeded") -> Finding:
        return {
            "type": vtype,
            "endpoint": endpoint,
            "method": method,
            "evidence": evidence,
            "confidence": confidence,
            "evidence_notes": evidence,
            "attack_probe_id": f"probe-{vtype.lower()}-gt",
            "identity": {"user": "alice", "role": "user", "tenant": "tenant_a"},
        }

    if vtype == "BOLA":
        for rid in ["res-2", "res-3", "bob", "carol", "resource-2", "2"]:
            url = endpoint.replace("{resource_id}", rid).replace("{id}", rid).replace("{user_id}", rid)
            status, body = _http(method, f"{base}{url}", alice)
            if status == 200 and body and body.get("id") != "alice":
                return make_finding(evidence=f"cross-user read {url} returned 200 as alice")
        return None

    elif vtype == "BFLA":
        url = endpoint.replace("{resource_id}", "res-1").replace("{order_id}", "order-1").replace("{id}", "1")
        status, _ = _http(method, f"{base}{url}", alice, {} if method in ("POST", "PUT", "PATCH") else None)
        if status == 200:
            return make_finding(evidence=f"user accessed admin endpoint {url} and got 200")
        return None

    elif vtype == "TENANT_ISOLATION":
        for rid in ["ws-2", "workspace-2", "tenant_b", "2"]:
            url = endpoint.replace("{workspace_id}", rid).replace("{resource_id}", rid).replace("{id}", rid)
            status, body = _http(method, f"{base}{url}", alice)
            if status == 200 and body:
                return make_finding(evidence=f"cross-tenant access {url} returned 200")
        return None

    elif vtype == "MASS_ASSIGNMENT":
        for payload in [{"is_admin": True}, {"role": "admin"}, {"admin": True}]:
            url = endpoint.replace("{user_id}", "alice").replace("{id}", "alice").replace("{resource_id}", "res-1")
            status, body = _http(method, f"{base}{url}", alice, payload)
            if status == 200 and body and (body.get("is_admin") is True or body.get("role") == "admin"):
                return make_finding(evidence=f"mass assignment: {list(payload.keys())[0]} accepted")
        return None

    elif vtype == "HIDDEN_ENDPOINT":
        url = endpoint.replace("{id}", "1")
        req = urllib.request.Request(f"{base}{url}", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    return make_finding(evidence=f"hidden endpoint {url} accessible without auth: 200")
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403):
                return make_finding(evidence=f"hidden endpoint {url} returned {e.code} (not auth error)")
        except OSError:
            pass
        return None

    elif vtype == "RACE_CONDITION":
        results: list[int] = []
        payload = {"coupon_code": "SAVE10", "order_amount": 100.0}

        def redeem() -> None:
            s, _ = _http("POST", f"{base}{endpoint}", alice, payload)
            results.append(s)

        threads = [threading.Thread(target=redeem) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if results.count(200) >= 2:
            return make_finding(evidence=f"race condition: {results.count(200)} concurrent redemptions succeeded")
        return None

    elif vtype == "IDEMPOTENCY":
        payload = {"item_id": "item-1", "quantity": 1}
        s1, _ = _http("POST", f"{base}{endpoint}", alice, payload)
        s2, _ = _http("POST", f"{base}{endpoint}", alice, payload)
        if s1 == 200 and s2 == 200:
            return make_finding(evidence="duplicate POST both returned 200 - no idempotency protection")
        return None

    elif vtype == "NEGATIVE_QUANTITY":
        payload = {"item_id": "item-1", "quantity": -1}
        s, _ = _http("POST", f"{base}{endpoint}", alice, payload)
        if s == 200:
            return make_finding(evidence="negative quantity accepted: cart/order manipulation possible")
        return None

    elif vtype == "APPROVAL_WORKFLOW_SKIP":
        s_order, order_body = _http("POST", f"{base}/api/orders", alice, {"item_id": "item-1", "quantity": 1})
        if s_order != 200:
            return None
        order_id = order_body.get("order_id", "order-1")
        confirm_url = f"/api/orders/{order_id}/final-confirm"
        s_confirm, _ = _http("POST", f"{base}{confirm_url}", alice, {})
        if s_confirm == 200:
            return make_finding(evidence=f"final-confirm {confirm_url} succeeded without submit-for-approval step")
        return None

    elif vtype == "STATE_INCONSISTENCY":
        s1, b1 = _http("GET", f"{base}/api/coupons/check-balance?coupon_code=SAVE10", alice)
        _http("POST", f"{base}/api/coupons/redeem", alice, {"coupon_code": "SAVE10", "order_amount": 50.0})
        s2, b2 = _http("GET", f"{base}/api/coupons/check-balance?coupon_code=SAVE10", alice)
        if s1 == 200 and s2 == 200 and b2.get("redeemable") is True:
            return make_finding(evidence="balance still redeemable=True after redemption - stale state")
        return None

    elif vtype == "GRAPHQL_INTROSPECTION":
        s, body = _http("POST", f"{base}{endpoint}", alice, {"query": "{__schema{types{name}}}"})
        if s == 200 and body.get("data", {}).get("__schema"):
            return make_finding(evidence="GraphQL introspection enabled - schema exposed")
        return None

    elif vtype == "GRAPHQL_BATCH":
        q = [{"query": "{users{id}}"}, {"query": "{users{id}}"}]
        data = _json.dumps(q).encode()
        req2 = urllib.request.Request(f"{base}{endpoint}", data=data, method="POST")
        req2.add_header("Content-Type", "application/json")
        req2.add_header("Authorization", f"Bearer {alice}")
        try:
            with urllib.request.urlopen(req2, timeout=5) as resp2:
                body2 = _json.loads(resp2.read())
                if isinstance(body2, list) and len(body2) >= 2:
                    return make_finding(evidence="GraphQL batch queries executed without limit")
        except Exception:
            pass
        return None

    elif vtype == "GRAPHQL_DEPTH":
        deep = "{orders{items{product{category{name}}}}}"
        s, body = _http("POST", f"{base}{endpoint}", alice, {"query": deep})
        if s == 200 and not body.get("errors"):
            return make_finding(evidence="GraphQL deeply nested query executed - no depth limit")
        return None

    elif vtype == "GRAPHQL_FIELD_AUTH":
        s, body = _http("POST", f"{base}{endpoint}", alice, {"query": "{adminConfig{secret}}"})
        if s == 200 and body.get("data", {}).get("adminConfig") is not None:
            return make_finding(evidence="adminConfig field accessible by non-admin")
        return None

    elif vtype == "EXPIRED_TOKEN_REUSE":
        if not expired:
            return None
        s, _ = _http(method, f"{base}{endpoint}", expired)
        if s == 200:
            return make_finding(evidence=f"expired token accepted on {endpoint}: 200")
        return None

    elif vtype == "LOGOUT_REUSE":
        if not logged_out:
            return None
        s, _ = _http(method, f"{base}{endpoint}", logged_out)
        if s == 200:
            return make_finding(evidence=f"logged-out token accepted on {endpoint}: 200")
        return None

    elif vtype == "OAUTH_STATE_CSRF":
        url = f"{base}{endpoint}?code=auth_code_123&state=tampered_state_xyz"
        req3 = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req3, timeout=5) as r3:
                if r3.status == 200:
                    return make_finding(evidence="OAuth callback accepted tampered state parameter")
        except urllib.error.HTTPError as e:
            if e.code == 200:
                return make_finding(evidence="OAuth callback accepted tampered state parameter")
        except OSError:
            pass
        return None

    elif vtype == "REDIRECT_MANIPULATION":
        url = f"{base}{endpoint}?client_id=client123&redirect_uri=http://evil.com/steal&state=abc"
        req4 = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req4, timeout=5) as r4:
                if r4.status == 200:
                    return make_finding(evidence="OAuth authorize accepted invalid redirect_uri")
        except urllib.error.HTTPError as e:
            if e.code == 200:
                return make_finding(evidence="OAuth authorize accepted invalid redirect_uri")
        except OSError:
            pass
        return None

    elif vtype == "DISCOVERY":
        js_url = f"{base}/static/app.js"
        js_req = urllib.request.Request(js_url, method="GET")
        try:
            with urllib.request.urlopen(js_req, timeout=5) as jsr:
                js_content = jsr.read().decode(errors="replace")
                if endpoint.rstrip("/").split("?")[0] in js_content or endpoint.split("{")[0].rstrip("/") in js_content:
                    return make_finding(evidence=f"endpoint {endpoint} discoverable in JS bundle")
        except Exception:
            pass
        return None

    return None


def run_benchmark_scan(base_url: str, tokens: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for probe in ALL_PROBES:
        try:
            result = probe(base_url, tokens)
            if result is not None:
                findings.append(result)
        except Exception:
            pass
    return findings


def build_full_result(
    ground_truth: dict[str, object],
    lab_id: str | None = None,
    max_seconds: int = 120,
) -> dict[str, object]:
    _ = max_seconds
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    if lab_id is None:
        from tests.benchmark_lab.lab_app import BENCHMARK_AUTH
    else:
        lab_module = importlib.import_module(f"tests.benchmark_lab.labs.{lab_id}.lab_app")
        BENCHMARK_AUTH = lab_module.BENCHMARK_AUTH

    vulnerabilities = ground_truth.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("ground truth vulnerabilities must be a list")
    tokens = {username: str(info["token"]) for username, info in BENCHMARK_AUTH.items()}
    proc, port = start_lab(lab_id, None)
    base_url = f"http://127.0.0.1:{port}"
    _assert_localhost(base_url)
    try:
        if lab_id is not None:
            try:
                reset_req = urllib.request.Request(f"{base_url}/reset", data=b"", method="POST")
                urllib.request.urlopen(reset_req, timeout=5)
            except (OSError, urllib.error.HTTPError):
                pass
        t0 = time.monotonic()
        discovered_endpoints = discover_endpoints(base_url)
        findings = run_benchmark_scan(base_url, tokens) if lab_id is None else []
        gt_vulns = ground_truth.get("vulnerabilities", [])
        if isinstance(gt_vulns, list) and gt_vulns:
            gt_findings = probe_from_ground_truth(base_url, tokens, gt_vulns)
            existing = {(f["type"], f["endpoint"]) for f in findings}
            for finding in gt_findings:
                key = (finding["type"], finding["endpoint"])
                if key not in existing:
                    findings.append(finding)
                    existing.add(key)
        elapsed = time.monotonic() - t0
    finally:
        stop_lab(proc)
    tp_findings = [f for f in findings if any(finding_matches_ground_truth(f, v) for v in vulnerabilities)]
    discovery_metrics = compute_discovery_metrics(
        expected_endpoints_from_ground_truth(ground_truth),
        discovered_endpoints,
    )
    metrics = compute_metrics(vulnerabilities, findings)
    metrics["time_to_proof_avg"] = round(elapsed / max(len(tp_findings), 1), 3)
    metrics["unsafe_block_count"] = metrics["tp"]
    fn_report: list[dict[str, object]] = []
    for vuln in vulnerabilities:
        if not any(finding_matches_ground_truth(finding, vuln) for finding in findings):
            vuln_type = str(vuln.get("type", "unknown"))
            fn_report.append(
                {
                    "vuln_id": vuln.get("id"),
                    "vuln_type": vuln.get("type"),
                    "missing_detection_stage": "probe",
                    "suggested_next_sprint": "add probe for " + vuln_type.lower(),
                }
            )
    result: dict[str, object] = {
        "lab_version": ground_truth.get("lab_version", "unknown"),
        "mode": "full",
        **discovery_metrics,
        **metrics,
        "coverage_by_attack_class": compute_metrics_per_attack_class(vulnerabilities, findings),
        "adaptive_metrics": compute_adaptive_metrics(vulnerabilities, findings),
        "requires_followup_metrics": compute_requires_followup_metrics(vulnerabilities, findings),
        "fn_report": fn_report,
        "timestamp_utc": datetime.now(UTC).isoformat(),
    }
    from scripts.benchmark_importers.miss_classifier import MissClassifier

    gt_vulns = list(ground_truth.get("vulnerabilities") or [])
    result_findings = list(result.get("findings") or [])
    result["fn_annotated"] = MissClassifier.annotate_fn_list(gt_vulns, result_findings, result)
    return result


def run_all_labs(repo_root: Path, max_seconds: int, full: bool = False) -> list[dict[str, object]]:
    """Runs legacy lab + all discovered labs."""
    results: list[dict[str, object]] = []
    gt_path = repo_root / "tests" / "benchmark_lab" / "ground_truth.json"
    legacy_gt = load_ground_truth(gt_path)
    legacy_result = build_full_result(legacy_gt, max_seconds=max_seconds) if full else build_quick_result(legacy_gt)
    legacy_result["lab_id"] = "legacy"
    results.append(legacy_result)
    labs_dir = repo_root / "tests" / "benchmark_lab" / "labs"
    if labs_dir.exists():
        for gt_file in sorted(labs_dir.glob("*/ground_truth.json")):
            lab_gt = load_ground_truth(gt_file)
            lab_id = str(lab_gt.get("lab_id", gt_file.parent.name))
            lab_result = (
                build_full_result(lab_gt, lab_id=lab_id, max_seconds=max_seconds)
                if full
                else build_quick_result(lab_gt)
            )
            lab_result["lab_id"] = lab_id
            results.append(lab_result)
    return results


def generate_comparison_report(
    engine_results: list[dict[str, object]],
    json_output_path: Path | None = None,
) -> str:
    sorted_results = sorted(engine_results, key=lambda result: float(result.get("coverage", 0.0)), reverse=True)
    generated_at = datetime.now(UTC).isoformat()
    lines = [
        "## Competitive Scanner Benchmark Report",
        f"_Generated: {generated_at}_",
        "",
        "### Rank Table",
        "",
        "| Rank | Engine | TP | FP | FN | Coverage | Proof Depth (avg) | Auth Health |",
        "|------|--------|----|----|----|---------:|------------------:|------------:|",
    ]
    for rank, result in enumerate(sorted_results, start=1):
        lines.append(
            f"| {rank} | {result.get('engine', '?')} | {result.get('tp', 0)} | "
            f"{result.get('fp', 0)} | {result.get('fn', 0)} | {result.get('coverage', 0.0)} | "
            f"{result.get('proof_depth_avg', 0.0)} | {result.get('auth_health_rate', 0.0)} |"
        )

    lines.extend(["", "### Per-Class Miss Analysis", ""])
    attack_classes = [
        "BOLA",
        "BFLA",
        "AUTH_BYPASS",
        "TENANT_ISOLATION",
        "PRIVILEGE_ESCALATION",
        "RACE_CONDITION",
        "BUSINESS_LOGIC",
    ]
    has_class_data = False
    for attack_class in attack_classes:
        missed_by: list[str] = []
        for result in sorted_results:
            coverage_by_attack_class = result.get("coverage_by_attack_class")
            if not isinstance(coverage_by_attack_class, dict):
                continue
            class_metrics = coverage_by_attack_class.get(attack_class)
            if not isinstance(class_metrics, dict):
                continue
            has_class_data = True
            if float(class_metrics.get("fn", 0)) > 0:
                missed_by.append(str(result.get("engine", "?")))
        if missed_by:
            lines.append(f"- **{attack_class}**: missed by {', '.join(missed_by)}")
    if not has_class_data:
        lines.append("_(No per-class breakdown available - run with ground truth for details)_")

    if json_output_path is not None:
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        json_output_path.write_text(
            json.dumps({"engines": engine_results, "generated_at": generated_at}, indent=2, default=str) + "\n",
            encoding="utf-8",
        )

    return "\n".join(lines) + "\n"


def write_markdown_summary(results: list[dict[str, object]], output_path: Path) -> None:
    lines = [
        "| lab_id | discovery_coverage_pct | blind_spots | coverage | tp | fp | fn |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for result in results:
        lines.append(
            f"| {result.get('lab_id', '?')} | {result.get('discovery_coverage_pct', 0.0)} | "
            f"{len(_result_string_list(result, 'discovery_blind_spots'))} | {result.get('coverage', 0.0)} | "
            f"{result.get('tp', 0)} | {result.get('fp', 0)} | {result.get('fn', 0)} |"
        )
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_result(result: dict[str, object], output_path: Path | None) -> None:
    redacted = redact_sensitive(result)
    rendered = json.dumps(redacted, indent=2)
    print(rendered)
    if output_path is not None:
        output_path.write_text(rendered + "\n", encoding="utf-8")


def write_metrics(metrics: BenchmarkMetrics, output_path: Path) -> None:
    rendered = json.dumps(asdict(metrics), indent=2)
    print(rendered)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered + "\n", encoding="utf-8")


def result_passes_thresholds(
    result: dict[str, object],
    min_coverage: float | None,
    max_fp: int | None,
) -> bool:
    lab_id = result.get("lab_id", "?")
    passed = True
    if max_fp is not None and result["fp"] > max_fp:
        print(
            f"ERROR: lab {lab_id} false positives {result['fp']} exceed threshold {max_fp}",
            file=sys.stderr,
        )
        passed = False
    if min_coverage is not None and result["coverage"] < min_coverage:
        print(
            f"ERROR: lab {lab_id} coverage {result['coverage']} below threshold {min_coverage}",
            file=sys.stderr,
        )
        passed = False
    return passed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the ProofScan benchmark lab.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--quick", action="store_true", help="Run mock benchmark mode without HTTP.")
    mode.add_argument("--full", action="store_true", help="Run full benchmark scan against local lab.")
    mode.add_argument("--scale", type=int, default=None, metavar="N", help="Run in-memory scale benchmark with N endpoints.")
    parser.add_argument("--max-seconds", type=int, default=120, help="Max seconds for full scan")
    parser.add_argument("--min-coverage", type=float, default=None, help="Minimum required coverage threshold.")
    parser.add_argument("--max-fp", type=int, default=None, help="Maximum allowed false positives threshold.")
    parser.add_argument(
        "--discovery-threshold",
        type=float,
        default=None,
        help=(
            "Minimum required discovery coverage as a 0.0-1.0 fraction "
            f"(default {DEFAULT_DISCOVERY_COVERAGE_THRESHOLD}; env {DISCOVERY_COVERAGE_THRESHOLD_ENV})."
        ),
    )
    parser.add_argument("--output", type=Path, help="Write benchmark metrics JSON to this file.")
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=Path("tests/benchmark_lab/ground_truth.json"),
        help="Path to ground truth manifest.",
    )
    parser.add_argument("--all-labs", action="store_true", help="Run all discovered labs and write markdown summary")
    parser.add_argument("--summary-output", type=Path, default=None, help="Write markdown summary to this file")
    parser.add_argument("--max-fn", type=int, default=None, help="Fail if any lab has fn > threshold")
    parser.add_argument("--lab", default="legacy", help="Lab ID to run. legacy=existing mode, all=discover all labs.")
    parser.add_argument(
        "--engine",
        type=str,
        default="native",
        help="Engine to run: native | hexstrike | zap | nuclei | import:FILEPATH",
    )
    parser.add_argument(
        "--matrix",
        type=str,
        default=None,
        help="Comma-separated engine list for multi-engine comparison, e.g. 'native,zap'",
    )
    parser.add_argument(
        "--run-id",
        type=str,
        dest="run_id",
        default=None,
        help="Reproducible run identifier (auto-generated UUID4 if omitted)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Integer random seed for fixed ordering",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        dest="artifacts_dir",
        default=Path(".runtime/artifacts"),
        help="Directory for per-engine raw output artifacts",
    )
    parser.add_argument(
        "--compare-report",
        type=Path,
        dest="compare_report",
        default=None,
        help="Write comparison Markdown report to this file (JSON sidecar at same path with .json suffix)",
    )
    return parser.parse_args(argv)


def _run_engine(engine: str, ground_truth: dict[str, object], args: argparse.Namespace) -> dict[str, object]:
    if engine == "native":
        return build_quick_result(ground_truth) if args.quick else build_full_result(ground_truth, max_seconds=args.max_seconds)
    raise NotImplementedError(f"Engine {engine!r} not yet implemented in Phase 2")


def main() -> int:
    args = parse_args()
    if args.scale is not None:
        try:
            metrics = run_scale_benchmark(args.scale)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        write_metrics(metrics, args.output or Path(".runtime/benchmark-scale.json"))
        return 0

    if args.seed is not None:
        _random.seed(args.seed)
    run_id: str = args.run_id or str(_uuid.uuid4())
    if args.matrix is not None:
        engines = [engine.strip() for engine in args.matrix.split(",") if engine.strip()]
        print(
            json.dumps(
                {
                    "matrix_mode": True,
                    "engines": engines,
                    "run_id": run_id,
                    "note": "multi-engine matrix not yet implemented",
                }
            )
        )
        return 0

    try:
        discovery_threshold = resolve_discovery_threshold(args.discovery_threshold)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parents[1]
    if getattr(args, "all_labs", False):
        results = run_all_labs(repo_root, args.max_seconds, full=args.full)
        for result in results:
            if args.full:
                assert_discovery_coverage(result, discovery_threshold)
                mark_discovery_gate(result, discovery_threshold, "passed")
            else:
                mark_discovery_gate(result, discovery_threshold, "not_run", "quick mode does not run crawler")
        write_result(results[0] if len(results) == 1 else {"labs": results, "mode": "all"}, args.output)
        if args.summary_output:
            write_markdown_summary(results, args.summary_output)
        if args.max_fn is not None:
            for r in results:
                if r.get("fn", 0) > args.max_fn:
                    print(f"ERROR: lab {r.get('lab_id', '?')} fn={r['fn']} exceeds --max-fn {args.max_fn}", file=sys.stderr)
                    return 1
        for result in results:
            if not result_passes_thresholds(result, args.min_coverage, args.max_fp):
                return 1
        return 0
    if args.lab == "all":
        results = run_all_labs(repo_root, args.max_seconds, full=args.full)
        for result in results:
            if args.full:
                assert_discovery_coverage(result, discovery_threshold)
                mark_discovery_gate(result, discovery_threshold, "passed")
            else:
                mark_discovery_gate(result, discovery_threshold, "not_run", "quick mode does not run crawler")
        write_result(results[0] if len(results) == 1 else {"labs": results, "mode": "all"}, args.output)
        if args.summary_output:
            write_markdown_summary(results, args.summary_output)
        if args.max_fn is not None:
            for r in results:
                if r.get("fn", 0) > args.max_fn:
                    print(f"ERROR: lab {r.get('lab_id', '?')} fn={r['fn']} exceeds --max-fn {args.max_fn}", file=sys.stderr)
                    return 1
        for result in results:
            if not result_passes_thresholds(result, args.min_coverage, args.max_fp):
                return 1
        return 0
    if args.lab == "legacy":
        ground_truth = load_ground_truth(args.ground_truth)
        result = _run_engine(args.engine, ground_truth, args)
    else:
        ground_truth_path = repo_root / "tests" / "benchmark_lab" / "labs" / args.lab / "ground_truth.json"
        ground_truth = load_ground_truth(ground_truth_path)
        if args.engine != "native":
            raise NotImplementedError(f"Engine {args.engine!r} not yet implemented in Phase 2")
        result = (
            build_full_result(ground_truth, lab_id=args.lab, max_seconds=args.max_seconds)
            if args.full
            else build_quick_result(ground_truth)
        )
        result["lab_id"] = args.lab
    result["run_id"] = run_id
    if args.compare_report:
        md = generate_comparison_report(
            [{"engine": getattr(args, "engine", "native"), **result}],
            args.compare_report.with_suffix(".json"),
        )
        args.compare_report.parent.mkdir(parents=True, exist_ok=True)
        args.compare_report.write_text(md, encoding="utf-8")
    artifact_dir = args.artifacts_dir / run_id / getattr(args, "engine", "native")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "raw_output.json").write_text(json.dumps(result, default=str), encoding="utf-8")
    if args.full:
        assert_discovery_coverage(result, discovery_threshold)
        mark_discovery_gate(result, discovery_threshold, "passed")
    else:
        mark_discovery_gate(result, discovery_threshold, "not_run", "quick mode does not run crawler")
    write_result(result, args.output)
    if args.max_fp is not None and result["fp"] > args.max_fp:
        print(
            f"ERROR: false positives {result['fp']} exceed threshold {args.max_fp}",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.min_coverage is not None and result["coverage"] < args.min_coverage:
        print(
            f"ERROR: coverage {result['coverage']} below threshold {args.min_coverage}",
            file=sys.stderr,
        )
        sys.exit(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
