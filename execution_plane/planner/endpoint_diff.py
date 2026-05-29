from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class EndpointDiff:
    added: list[str]
    modified: list[str]
    removed: list[str]
    unchanged: list[str]

    @property
    def changed(self) -> list[str]:
        return [*self.added, *self.modified]


def infer_from_openapi_diff(old_spec: dict[str, Any], new_spec: dict[str, Any]) -> EndpointDiff:
    old_paths = old_spec.get("paths", {})
    new_paths = new_spec.get("paths", {})

    old_keys = set(old_paths.keys())
    new_keys = set(new_paths.keys())

    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)

    common = old_keys & new_keys
    modified = sorted(path for path in common if old_paths[path] != new_paths[path])
    unchanged = sorted(path for path in common if old_paths[path] == new_paths[path])

    return EndpointDiff(added=added, modified=modified, removed=removed, unchanged=unchanged)


def infer_from_route_list_diff(old_routes: list[str], new_routes: list[str]) -> EndpointDiff:
    old_set = set(old_routes)
    new_set = set(new_routes)

    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    unchanged = sorted(old_set & new_set)
    return EndpointDiff(added=added, modified=[], removed=removed, unchanged=unchanged)


class DiffAwarePlanner:
    def __init__(self, diff: EndpointDiff) -> None:
        self.diff = diff

    def filter_endpoints(self, endpoints: list[str]) -> list[str]:
        changed = set(self.diff.changed)
        if not changed:
            return endpoints
        return [endpoint for endpoint in endpoints if endpoint in changed]
