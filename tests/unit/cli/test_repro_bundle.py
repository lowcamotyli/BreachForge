from __future__ import annotations

import json

from cli.repro_bundle import ReproBundle


def test_collect_creates_files(tmp_path) -> None:
    scan_output = tmp_path / "scan.json"
    scan_output.write_text(json.dumps({"findings": [{"result": "tp"}]}), encoding="utf-8")
    bundle = ReproBundle(output_dir=tmp_path / "bundle")

    bundle.collect(scan_output)

    assert (bundle.output_dir / "raw_output.json").exists()
    assert (bundle.output_dir / "normalized_findings.json").exists()
    assert (bundle.output_dir / "metrics.json").exists()
    assert (bundle.output_dir / "env_metadata.json").exists()


def test_sign_is_stable(tmp_path) -> None:
    scan_output = tmp_path / "scan.json"
    scan_output.write_text(json.dumps({"findings": [{"result": "tp"}]}), encoding="utf-8")
    bundle = ReproBundle(output_dir=tmp_path / "bundle")
    bundle.collect(scan_output)

    assert bundle.sign() == bundle.sign()


def test_export_creates_manifest(tmp_path) -> None:
    scan_output = tmp_path / "scan.json"
    scan_output.write_text(json.dumps({"findings": [{"result": "tp"}]}), encoding="utf-8")
    bundle = ReproBundle(output_dir=tmp_path / "bundle")

    bundle.collect(scan_output)
    bundle.export()
    manifest = json.loads((bundle.output_dir / "manifest.json").read_text(encoding="utf-8"))

    assert "bundle_signature" in manifest
    assert "files" in manifest
