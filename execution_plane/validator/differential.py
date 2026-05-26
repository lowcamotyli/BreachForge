from __future__ import annotations

import difflib
from dataclasses import dataclass, field
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


@dataclass
class StructuralDiff:
    added_keys: list[str] = field(default_factory=list)
    removed_keys: list[str] = field(default_factory=list)
    type_changed_keys: list[str] = field(default_factory=list)
    value_changed_keys: list[str] = field(default_factory=list)
    list_length_changes: dict[str, tuple[int, int]] = field(default_factory=dict)

    def has_meaningful_change(self, volatile_keys: frozenset[str] | None = None) -> bool:
        default_volatile_keys = frozenset(
            {
                "timestamp",
                "updated_at",
                "created_at",
                "request_id",
                "trace_id",
                "server_time",
                "nonce",
                "etag",
            }
        )
        excluded_keys = volatile_keys if volatile_keys is not None else default_volatile_keys

        return any(
            self._has_nonvolatile_path(paths, excluded_keys)
            for paths in (
                self.added_keys,
                self.removed_keys,
                self.type_changed_keys,
                self.value_changed_keys,
                self.list_length_changes.keys(),
            )
        )

    def _has_nonvolatile_path(self, paths: Any, volatile_keys: frozenset[str]) -> bool:
        return any(not self._is_volatile_path(path, volatile_keys) for path in paths)

    def _is_volatile_path(self, path: str, volatile_keys: frozenset[str]) -> bool:
        return path in volatile_keys or path.rsplit(".", maxsplit=1)[-1] in volatile_keys


class JsonStructuralComparator:
    def compare(
        self,
        before: dict[str, Any],
        after: dict[str, Any],
        depth: int = 0,
        max_depth: int = 5,
    ) -> StructuralDiff:
        diff = StructuralDiff()
        self._compare_dicts(before, after, diff, prefix="", depth=depth, max_depth=max_depth)
        return diff

    def _compare_dicts(
        self,
        before: dict[str, Any],
        after: dict[str, Any],
        diff: StructuralDiff,
        prefix: str,
        depth: int,
        max_depth: int,
    ) -> None:
        before_keys = set(before.keys())
        after_keys = set(after.keys())

        for key in sorted(after_keys - before_keys):
            diff.added_keys.append(self._path(prefix, key))

        for key in sorted(before_keys - after_keys):
            diff.removed_keys.append(self._path(prefix, key))

        for key in sorted(before_keys & after_keys):
            path = self._path(prefix, key)
            before_value = before[key]
            after_value = after[key]

            if type(before_value) is not type(after_value):
                diff.type_changed_keys.append(path)
                continue

            if isinstance(before_value, dict):
                if depth >= max_depth:
                    if before_value != after_value:
                        diff.value_changed_keys.append(path)
                    continue

                self._compare_dicts(
                    before_value,
                    after_value,
                    diff,
                    prefix=path,
                    depth=depth + 1,
                    max_depth=max_depth,
                )
                continue

            if isinstance(before_value, list):
                if len(before_value) != len(after_value):
                    diff.list_length_changes[path] = (len(before_value), len(after_value))
                elif before_value != after_value:
                    diff.value_changed_keys.append(path)
                continue

            if before_value != after_value:
                diff.value_changed_keys.append(path)

    def _path(self, prefix: str, key: str) -> str:
        return f"{prefix}.{key}" if prefix else key


@dataclass
class TextDiff:
    length_bucket_before: str
    length_bucket_after: str
    bucket_changed: bool
    normalized_similarity: float


class TextComparator:
    BUCKETS = [
        ("0", 0, 0),
        ("tiny", 1, 100),
        ("small", 101, 1000),
        ("medium", 1001, 10000),
        ("large", 10001, float("inf")),
    ]

    def compare(self, before: str, after: str) -> TextDiff:
        before_bucket = self._bucket(before)
        after_bucket = self._bucket(after)
        return TextDiff(
            length_bucket_before=before_bucket,
            length_bucket_after=after_bucket,
            bucket_changed=before_bucket != after_bucket,
            normalized_similarity=difflib.SequenceMatcher(None, before, after).ratio(),
        )

    def _bucket(self, text: str) -> str:
        length = len(text)
        for label, minimum, maximum in self.BUCKETS:
            if minimum <= length <= maximum:
                return label
        return "large"


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
