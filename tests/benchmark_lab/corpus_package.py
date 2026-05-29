from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
from pathlib import Path


@dataclass(frozen=True)
class CorpusPackage:
    lab_root: Path
    corpus_version: str

    def compute_ground_truth_hash(self) -> str:
        ground_truth_path = self._ground_truth_path()
        return hashlib.sha256(ground_truth_path.read_bytes()).hexdigest()

    def list_labs(self) -> list[str]:
        labs_root = self.lab_root / "labs"
        if not labs_root.is_dir():
            return []

        labs: list[str] = []
        for lab_dir in labs_root.iterdir():
            if not lab_dir.is_dir():
                continue
            if (lab_dir / "manifest.json").is_file() or (lab_dir / "ground_truth.json").is_file():
                labs.append(lab_dir.name)
        return sorted(labs)

    def generate_manifest(self) -> dict[str, object]:
        return {
            "corpus_version": self.corpus_version,
            "ground_truth_hash": self.compute_ground_truth_hash(),
            "labs": self.list_labs(),
            "generated_at": datetime.now(UTC).isoformat(),
        }

    def _ground_truth_path(self) -> Path:
        ground_truth_path = self.lab_root / "ground_truth.json"
        if not ground_truth_path.is_file():
            raise ValueError(f"ground_truth.json missing at {ground_truth_path}")
        return ground_truth_path
