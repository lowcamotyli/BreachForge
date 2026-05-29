from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class InventoryNode:
    service: str
    repo: str | None
    endpoint_pattern: str
    method: str
    operations: list[str] = field(default_factory=list)
    owner_team: str = "unknown"
    owner_service: str = "unknown"
    owner_confidence: float = 0.0
    owner_source: str = "unknown"
    finding_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    source: str = "unknown"


@dataclass
class InventoryGraph:
    nodes: list[InventoryNode] = field(default_factory=list)

    def add_node(self, node: InventoryNode) -> None:
        self.nodes.append(node)

    def get_by_service(self, service: str) -> list[InventoryNode]:
        return [node for node in self.nodes if node.service == service]

    def get_by_owner(self, team: str) -> list[InventoryNode]:
        return [node for node in self.nodes if node.owner_team == team]

    def to_dict(self) -> list[dict]:
        return [asdict(node) for node in self.nodes]


@dataclass
class DriftReport:
    runtime_no_owner: list[str] = field(default_factory=list)
    repo_not_deployed: list[str] = field(default_factory=list)
    stale_version: list[str] = field(default_factory=list)


def detect_drift(
    graph: InventoryGraph,
    runtime_endpoints: list[str],
    code_endpoints: list[str],
) -> DriftReport:
    del code_endpoints  # Reserved for future drift dimensions.

    report = DriftReport()

    nodes_by_endpoint: dict[str, list[InventoryNode]] = {}
    for node in graph.nodes:
        nodes_by_endpoint.setdefault(node.endpoint_pattern, []).append(node)

    for endpoint in runtime_endpoints:
        matched_nodes = nodes_by_endpoint.get(endpoint, [])
        if not matched_nodes:
            report.runtime_no_owner.append(endpoint)
            continue

        best_confidence = max(node.owner_confidence for node in matched_nodes)
        if best_confidence < 0.3:
            report.runtime_no_owner.append(endpoint)

    runtime_set = set(runtime_endpoints)
    for node in graph.nodes:
        if node.source == "code_extractor" and node.endpoint_pattern not in runtime_set:
            report.repo_not_deployed.append(node.endpoint_pattern)

    version_pattern = re.compile(r"/v(\d+)/")
    canonical_versions: dict[str, set[int]] = {}
    for endpoint in runtime_endpoints:
        match = version_pattern.search(endpoint)
        if match is None:
            continue
        version = int(match.group(1))
        canonical_path = version_pattern.sub("/v{version}/", endpoint)
        canonical_versions.setdefault(canonical_path, set()).add(version)

    stale: set[str] = set()
    for canonical_path, versions in canonical_versions.items():
        if 1 in versions and any(version > 1 for version in versions):
            stale.add(canonical_path.replace("{version}", "1"))

    report.stale_version = sorted(stale)
    return report
