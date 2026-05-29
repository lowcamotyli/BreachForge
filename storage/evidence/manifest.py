from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


class EvidenceManifest:
    """Computes and verifies SHA-256 integrity hashes for evidence bundles."""

    SCHEMA_VERSION = "1.0"

    def build_manifest(
        self,
        probes: list[dict[str, Any]],
        artifacts: list[dict[str, Any]],
        report_data: dict[str, Any],
    ) -> dict[str, Any]:
        probes_hash = self._hash_item(probes)
        artifacts_hash = self._hash_item(artifacts)
        report_hash = self._hash_item(report_data)
        partial: dict[str, Any] = {
            "schema_version": self.SCHEMA_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "probe_count": len(probes),
            "artifact_count": len(artifacts),
            "hashes": {
                "probes": probes_hash,
                "artifacts": artifacts_hash,
                "report": report_hash,
            },
        }
        partial["hashes"]["manifest"] = self._hash_item(partial)
        return partial

    def verify(
        self,
        manifest: dict[str, Any],
        probes: list[dict[str, Any]],
        artifacts: list[dict[str, Any]],
        report_data: dict[str, Any],
    ) -> bool:
        rebuilt = self.build_manifest(probes, artifacts, report_data)
        original = {k: v for k, v in manifest.get("hashes", {}).items() if k != "manifest"}
        expected = {k: v for k, v in rebuilt.get("hashes", {}).items() if k != "manifest"}
        return original == expected

    def _hash_item(self, obj: Any) -> str:
        serialized = json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()
