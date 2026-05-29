from __future__ import annotations

from pathlib import Path

import pytest

from tests.benchmark_lab.corpus_package import CorpusPackage


REPO_ROOT = Path(__file__).resolve().parents[2]
LAB_ROOT = REPO_ROOT / "tests" / "benchmark_lab"
COMPOSE_PATH = REPO_ROOT / "docker" / "benchmark" / "docker-compose.benchmark.yml"
EXPECTED_LABS = ["api_saas", "auth_oauth", "business_race", "graphql", "spa_har"]


@pytest.fixture
def corpus_package() -> CorpusPackage:
    return CorpusPackage(lab_root=LAB_ROOT, corpus_version="1.0.0")


def test_ground_truth_exists(corpus_package: CorpusPackage) -> None:
    assert (corpus_package.lab_root / "ground_truth.json").is_file()


def test_ground_truth_hash_stable(corpus_package: CorpusPackage) -> None:
    first_hash = corpus_package.compute_ground_truth_hash()
    second_hash = corpus_package.compute_ground_truth_hash()

    assert first_hash == second_hash
    assert len(first_hash) == 64


def test_labs_listed(corpus_package: CorpusPackage) -> None:
    assert corpus_package.list_labs() == sorted(EXPECTED_LABS)


def test_manifest_schema(corpus_package: CorpusPackage) -> None:
    manifest = corpus_package.generate_manifest()

    assert set(manifest) == {"corpus_version", "ground_truth_hash", "labs", "generated_at"}
    assert manifest["corpus_version"] == "1.0.0"
    assert manifest["ground_truth_hash"] == corpus_package.compute_ground_truth_hash()
    assert manifest["labs"] == sorted(EXPECTED_LABS)
    assert isinstance(manifest["generated_at"], str)


def test_seed_documented() -> None:
    assert "BENCHMARK_SEED" in COMPOSE_PATH.read_text(encoding="utf-8")
