from __future__ import annotations

import json
from pathlib import Path

from tests.benchmark_lab.anti_gaming import AntiGamingConfig, AntiGamingTransformer


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "benchmark_lab" / "labs" / "api_saas" / "ground_truth.json"
GROUND_TRUTH_PATH = ROOT / "benchmark_lab" / "labs" / "api_saas" / "ground_truth.json"


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def test_transform_preserves_count() -> None:
    manifest = _load_json(MANIFEST_PATH)
    transformer = AntiGamingTransformer(AntiGamingConfig(seed=42))

    transformed = transformer.transform_manifest(manifest)

    assert len(transformed["vulnerabilities"]) == len(manifest["vulnerabilities"])


def test_transform_deterministic() -> None:
    manifest = _load_json(MANIFEST_PATH)

    t1 = AntiGamingTransformer(AntiGamingConfig(seed=123)).transform_manifest(manifest)
    t2 = AntiGamingTransformer(AntiGamingConfig(seed=123)).transform_manifest(manifest)

    assert t1 == t2


def test_transform_different_seeds() -> None:
    manifest = _load_json(MANIFEST_PATH)

    t1 = AntiGamingTransformer(AntiGamingConfig(seed=1)).transform_manifest(manifest)
    t2 = AntiGamingTransformer(AntiGamingConfig(seed=2)).transform_manifest(manifest)

    ids1 = {v["id"] for v in t1["vulnerabilities"]}
    ids2 = {v["id"] for v in t2["vulnerabilities"]}

    assert ids1 != ids2


def test_ground_truth_ids_match_manifest() -> None:
    manifest = _load_json(MANIFEST_PATH)
    gt = _load_json(GROUND_TRUTH_PATH)
    transformer = AntiGamingTransformer(AntiGamingConfig(seed=7))

    transformed_manifest = transformer.transform_manifest(manifest)
    transformed_gt = transformer.transform_ground_truth(gt)

    manifest_ids = {v["id"] for v in transformed_manifest["vulnerabilities"]}
    gt_ids = {v["id"] for v in transformed_gt["vulnerabilities"]}

    assert gt_ids.issubset(manifest_ids)


def test_route_variants_differ() -> None:
    manifest = _load_json(MANIFEST_PATH)
    transformer = AntiGamingTransformer(AntiGamingConfig(seed=9))

    transformed = transformer.transform_manifest(manifest)

    assert transformed["expected_surface"] != manifest["expected_surface"]


def test_attack_classes_unchanged() -> None:
    manifest = _load_json(MANIFEST_PATH)
    transformer = AntiGamingTransformer(AntiGamingConfig(seed=9))

    transformed = transformer.transform_manifest(manifest)

    assert transformed["attack_classes"] == manifest["attack_classes"]
