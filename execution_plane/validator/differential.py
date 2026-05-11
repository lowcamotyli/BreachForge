from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class DifferentialProbeResult:
    baseline_identity: str
    challenger_identity: str
    baseline_status: int
    challenger_status: int
    status_differs: bool
    shape_differs: bool
    ownership_markers_differ: bool
    content_length_bucket_baseline: str
    content_length_bucket_challenger: str


class ResponseComparator:
    def compare(
        self,
        baseline_resp: httpx.Response,
        challenger_resp: httpx.Response,
        baseline_identity: str,
        challenger_identity: str,
    ) -> DifferentialProbeResult:
        baseline_json = self._safe_json_dict(baseline_resp)
        challenger_json = self._safe_json_dict(challenger_resp)

        shape_differs = False
        if baseline_json is not None and challenger_json is not None:
            shape_differs = set(baseline_json.keys()) != set(challenger_json.keys())

        ownership_markers_differ = False
        if baseline_json is not None and challenger_json is not None:
            ownership_fields = ["id", "user_id", "owner", "owner_id", "account_id"]
            for field in ownership_fields:
                if baseline_json.get(field) != challenger_json.get(field):
                    ownership_markers_differ = True
                    break

        return DifferentialProbeResult(
            baseline_identity=baseline_identity,
            challenger_identity=challenger_identity,
            baseline_status=baseline_resp.status_code,
            challenger_status=challenger_resp.status_code,
            status_differs=baseline_resp.status_code != challenger_resp.status_code,
            shape_differs=shape_differs,
            ownership_markers_differ=ownership_markers_differ,
            content_length_bucket_baseline=self._length_bucket(len(baseline_resp.content)),
            content_length_bucket_challenger=self._length_bucket(len(challenger_resp.content)),
        )

    def _safe_json_dict(self, response: httpx.Response) -> dict[str, Any] | None:
        try:
            data = response.json()
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def _length_bucket(self, length: int) -> str:
        if length == 0:
            return "0"
        if length <= 100:
            return "1-100"
        if length <= 1000:
            return "101-1000"
        return "1001+"
