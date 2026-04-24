from __future__ import annotations

from dataclasses import dataclass

from execution_plane.planner.attack_graph import AttackGraph


@dataclass(slots=True, frozen=True)
class AttackPath:
    node_ids: list[str]
    score: float


class PathRanker:
    def rank_paths(self, graph: AttackGraph, top_k: int = 10) -> list[AttackPath]:
        if top_k <= 0 or not graph.nodes or not graph.edges:
            return []

        roots = self._root_nodes(graph)
        path_scores: dict[tuple[str, ...], float] = {}

        for root_id in roots:
            self._collect_path_scores(
                graph=graph,
                node_id=root_id,
                visited={root_id},
                path=[root_id],
                cumulative_impact=1.0,
                cumulative_cost=0.0,
                path_scores=path_scores,
            )

        ranked_paths = [
            AttackPath(node_ids=list(path_node_ids), score=score)
            for path_node_ids, score in path_scores.items()
        ]
        ranked_paths.sort(key=lambda item: (-item.score, tuple(item.node_ids)))
        return ranked_paths[:top_k]

    def _root_nodes(self, graph: AttackGraph) -> list[str]:
        incoming_counts = graph.incoming_counts()
        roots = sorted(node_id for node_id, count in incoming_counts.items() if count == 0)
        if roots:
            return roots
        return sorted(graph.nodes.keys())

    def _collect_path_scores(
        self,
        *,
        graph: AttackGraph,
        node_id: str,
        visited: set[str],
        path: list[str],
        cumulative_impact: float,
        cumulative_cost: float,
        path_scores: dict[tuple[str, ...], float],
    ) -> None:
        outgoing_edges = sorted(
            graph.outgoing_edges(node_id),
            key=lambda edge: (edge.target_id, edge.action, edge.precondition),
        )

        for edge in outgoing_edges:
            if edge.target_id in visited:
                continue

            next_path = [*path, edge.target_id]
            next_visited = {*visited, edge.target_id}
            next_impact = cumulative_impact * edge.impact
            next_cost = cumulative_cost + edge.cost
            reachability = self._reachability_factor(graph=graph, node_id=edge.target_id)
            score = self._score(impact=next_impact, reachability=reachability, cost=next_cost)

            path_key = tuple(next_path)
            existing_score = path_scores.get(path_key)
            if existing_score is None or score > existing_score:
                path_scores[path_key] = score

            self._collect_path_scores(
                graph=graph,
                node_id=edge.target_id,
                visited=next_visited,
                path=next_path,
                cumulative_impact=next_impact,
                cumulative_cost=next_cost,
                path_scores=path_scores,
            )

    def _reachability_factor(self, *, graph: AttackGraph, node_id: str) -> float:
        total_nodes = len(graph.nodes)
        if total_nodes == 0:
            return 0.0

        reachable = graph.get_reachable(node_id)
        return (len(reachable) + 1) / total_nodes

    def _score(self, *, impact: float, reachability: float, cost: float) -> float:
        if cost <= 0:
            return 0.0
        return impact * reachability * (1 / cost)
