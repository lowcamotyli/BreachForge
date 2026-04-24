from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class AttackNode:
    id: str
    endpoint: str
    state: str
    identity: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class AttackEdge:
    source_id: str
    target_id: str
    action: str
    precondition: str
    impact: float = 1.0
    cost: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AttackGraph:
    scan_id: str
    nodes: dict[str, AttackNode] = field(default_factory=dict)
    edges: list[AttackEdge] = field(default_factory=list)
    _adjacency: dict[str, list[AttackEdge]] = field(default_factory=dict)

    def add_node(
        self,
        node_id: str,
        *,
        endpoint: str,
        state: str,
        identity: str,
        metadata: dict[str, Any] | None = None,
    ) -> AttackNode:
        if node_id in self.nodes:
            return self.nodes[node_id]

        node = AttackNode(
            id=node_id,
            endpoint=endpoint,
            state=state,
            identity=identity,
            metadata=dict(metadata or {}),
        )
        self.nodes[node_id] = node
        self._adjacency.setdefault(node_id, [])
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        *,
        action: str,
        precondition: str,
        impact: float = 1.0,
        cost: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> AttackEdge:
        if source_id not in self.nodes:
            raise KeyError(f"unknown source node: {source_id}")
        if target_id not in self.nodes:
            raise KeyError(f"unknown target node: {target_id}")
        if cost <= 0:
            raise ValueError("cost must be > 0")

        edge = AttackEdge(
            source_id=source_id,
            target_id=target_id,
            action=action,
            precondition=precondition,
            impact=impact,
            cost=cost,
            metadata=dict(metadata or {}),
        )
        self.edges.append(edge)
        self._adjacency.setdefault(source_id, []).append(edge)
        self._adjacency.setdefault(target_id, [])
        return edge

    def get_reachable(self, start_node_id: str) -> set[str]:
        if start_node_id not in self.nodes:
            raise KeyError(f"unknown node: {start_node_id}")

        visited: set[str] = set()
        queue: deque[str] = deque([start_node_id])

        while queue:
            node_id = queue.popleft()
            for edge in self._adjacency.get(node_id, []):
                if edge.target_id in visited:
                    continue
                visited.add(edge.target_id)
                queue.append(edge.target_id)

        return visited

    def outgoing_edges(self, node_id: str) -> list[AttackEdge]:
        return list(self._adjacency.get(node_id, []))

    def incoming_counts(self) -> dict[str, int]:
        counts = {node_id: 0 for node_id in self.nodes}
        for edge in self.edges:
            counts[edge.target_id] = counts.get(edge.target_id, 0) + 1
        return counts

    def serialize(self) -> dict[str, Any]:
        serialized_nodes = [
            {
                "id": node.id,
                "endpoint": node.endpoint,
                "state": node.state,
                "identity": node.identity,
                "metadata": dict(node.metadata),
            }
            for node in sorted(self.nodes.values(), key=lambda item: item.id)
        ]

        serialized_edges = [
            {
                "source_id": edge.source_id,
                "target_id": edge.target_id,
                "action": edge.action,
                "precondition": edge.precondition,
                "impact": edge.impact,
                "cost": edge.cost,
                "metadata": dict(edge.metadata),
            }
            for edge in sorted(
                self.edges,
                key=lambda item: (
                    item.source_id,
                    item.target_id,
                    item.action,
                    item.precondition,
                ),
            )
        ]

        return {
            "scan_id": self.scan_id,
            "nodes": serialized_nodes,
            "edges": serialized_edges,
        }

    @classmethod
    def deserialize(cls, payload: dict[str, Any]) -> AttackGraph:
        raw_scan_id = payload.get("scan_id")
        if not isinstance(raw_scan_id, str) or not raw_scan_id:
            raise ValueError("payload must include non-empty scan_id")

        graph = cls(scan_id=raw_scan_id)

        raw_nodes = payload.get("nodes", [])
        if not isinstance(raw_nodes, list):
            raise ValueError("payload.nodes must be a list")

        for raw_node in raw_nodes:
            if not isinstance(raw_node, dict):
                raise ValueError("payload.nodes entries must be objects")
            graph.add_node(
                str(raw_node["id"]),
                endpoint=str(raw_node["endpoint"]),
                state=str(raw_node["state"]),
                identity=str(raw_node["identity"]),
                metadata=dict(raw_node.get("metadata") or {}),
            )

        raw_edges = payload.get("edges", [])
        if not isinstance(raw_edges, list):
            raise ValueError("payload.edges must be a list")

        for raw_edge in raw_edges:
            if not isinstance(raw_edge, dict):
                raise ValueError("payload.edges entries must be objects")
            graph.add_edge(
                str(raw_edge["source_id"]),
                str(raw_edge["target_id"]),
                action=str(raw_edge["action"]),
                precondition=str(raw_edge["precondition"]),
                impact=float(raw_edge.get("impact", 1.0)),
                cost=float(raw_edge.get("cost", 1.0)),
                metadata=dict(raw_edge.get("metadata") or {}),
            )

        return graph
