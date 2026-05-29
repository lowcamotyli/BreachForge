from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import click
import httpx

from cli.bench import bench as bench_group
from cli.gate_runner import GateRunner

TERMINAL_STATUSES: set[str] = {"completed", "failed", "aborted"}


def _get_client() -> httpx.Client:
    api_url = os.getenv("BREACHFORGE_API_URL", "http://localhost:8000")
    token = os.getenv("BREACHFORGE_TOKEN")
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=api_url, headers=headers, timeout=30.0)


def _extract_scan_id(payload: dict[str, Any]) -> str:
    scan_id = payload.get("id") or payload.get("scan_id")
    if not scan_id:
        raise click.ClickException("Scan id not found in response payload")
    return str(scan_id)


def _extract_status(payload: dict[str, Any]) -> str:
    status = payload.get("status")
    if not status:
        raise click.ClickException("Scan status not found in response payload")
    return str(status)


def _extract_summary(report_payload: dict[str, Any]) -> dict[str, int]:
    summary_obj: Any = report_payload.get("summary", report_payload)
    if not isinstance(summary_obj, dict):
        return {}
    return {
        "new_critical": int(summary_obj.get("new_critical", 0)),
        "new_high": int(summary_obj.get("new_high", 0)),
        "auth_failures": int(summary_obj.get("auth_failures", 0)),
    }


@click.group(name="breachforge")
def breachforge() -> None:
    """BreachForge command line interface."""


@breachforge.group()
def scan() -> None:
    """Scan operations."""


@scan.command("create")
@click.option("--target", "target_url", required=True, type=str)
@click.option("--gate", "gate_config_path", type=str, default=None)
def create_scan(target_url: str, gate_config_path: str | None) -> None:
    payload: dict[str, str] = {"target_url": target_url}
    if gate_config_path:
        payload["gate_config_path"] = gate_config_path
    with _get_client() as client:
        response = client.post("/api/scans", json=payload)
        response.raise_for_status()
    scan_id = _extract_scan_id(response.json())
    click.echo(scan_id)


@scan.command("preflight")
@click.option("--scan-id", required=True, type=str)
def preflight_scan(scan_id: str) -> None:
    with _get_client() as client:
        response = client.get(f"/api/scans/{scan_id}/readiness")
        response.raise_for_status()
        payload = response.json()
    click.echo(json.dumps(payload, indent=2, sort_keys=True))


def _wait_for_scan(scan_id: str, timeout: int, poll_interval: int) -> tuple[str, dict[str, Any]]:
    deadline = time.monotonic() + timeout
    with _get_client() as client:
        while True:
            response = client.get(f"/api/scans/{scan_id}")
            response.raise_for_status()
            payload = response.json()
            status = _extract_status(payload)
            if status in TERMINAL_STATUSES:
                return status, payload
            if time.monotonic() >= deadline:
                raise click.ClickException(
                    f"Timed out waiting for scan {scan_id} after {timeout} seconds"
                )
            time.sleep(poll_interval)


@scan.command("wait")
@click.option("--scan-id", required=True, type=str)
@click.option("--timeout", type=int, default=300, show_default=True)
@click.option("--poll-interval", type=int, default=5, show_default=True)
def wait_scan(scan_id: str, timeout: int, poll_interval: int) -> None:
    status, _ = _wait_for_scan(scan_id=scan_id, timeout=timeout, poll_interval=poll_interval)
    click.echo(status)


@scan.command("export")
@click.option("--scan-id", required=True, type=str)
@click.option("--format", "report_format", type=str, default="json", show_default=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
def export_scan(scan_id: str, report_format: str, output: Path | None) -> None:
    with _get_client() as client:
        response = client.get(f"/api/reports/{scan_id}", params={"format": report_format})
        response.raise_for_status()
        payload = response.json()

    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if output is None:
        click.echo(rendered)
        return
    output.write_text(rendered + "\n", encoding="utf-8")


@scan.command("run")
@click.option("--target", "target_url", required=True, type=str)
@click.option("--gate", "gate_config_path", type=str, default=None)
@click.option("--timeout", type=int, default=300, show_default=True)
def run_scan(target_url: str, gate_config_path: str | None, timeout: int) -> None:
    create_payload: dict[str, str] = {"target_url": target_url}
    if gate_config_path:
        create_payload["gate_config_path"] = gate_config_path

    with _get_client() as client:
        create_response = client.post("/api/scans", json=create_payload)
        create_response.raise_for_status()
        scan_id = _extract_scan_id(create_response.json())
    click.echo(f"created scan: {scan_id}")

    status, _ = _wait_for_scan(scan_id=scan_id, timeout=timeout, poll_interval=5)
    click.echo(f"final status: {status}")
    if status != "completed":
        raise click.exceptions.Exit(2)

    with _get_client() as client:
        report_response = client.get(f"/api/reports/{scan_id}", params={"format": "json"})
        report_response.raise_for_status()
        report_payload = report_response.json()

    gate_runner = GateRunner.load(gate_config_path) if gate_config_path else GateRunner()
    passed, reason = gate_runner.evaluate(_extract_summary(report_payload))
    click.echo(reason)
    if passed:
        raise click.exceptions.Exit(0)
    raise click.exceptions.Exit(1)


breachforge.add_command(bench_group)


if __name__ == "__main__":
    breachforge()
