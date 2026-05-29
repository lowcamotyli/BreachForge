from control_plane.inventory_graph import DriftReport, InventoryGraph, InventoryNode, detect_drift


def _node(
    service: str,
    endpoint_pattern: str,
    owner_team: str,
    owner_confidence: float,
    *,
    source: str = "unknown",
    repo: str | None = None,
) -> InventoryNode:
    return InventoryNode(
        service=service,
        repo=repo,
        endpoint_pattern=endpoint_pattern,
        method="GET",
        operations=["read"],
        owner_team=owner_team,
        owner_service=service,
        owner_confidence=owner_confidence,
        owner_source="test",
        finding_ids=["F-1"],
        evidence_ids=["E-1"],
        source=source,
    )


def test_add_node_and_get_by_service() -> None:
    graph = InventoryGraph()
    node_a = _node("svc-a", "/api/v1/users", "team-a", 0.9)
    node_b = _node("svc-b", "/api/v1/orders", "team-b", 0.8)

    graph.add_node(node_a)
    graph.add_node(node_b)

    assert graph.get_by_service("svc-a") == [node_a]
    assert graph.get_by_service("svc-b") == [node_b]


def test_get_by_owner() -> None:
    graph = InventoryGraph(
        nodes=[
            _node("svc-a", "/api/v1/users", "team-a", 0.9),
            _node("svc-b", "/api/v1/orders", "team-b", 0.8),
            _node("svc-c", "/api/v1/products", "team-a", 0.7),
        ]
    )

    owned = graph.get_by_owner("team-a")
    assert [node.service for node in owned] == ["svc-a", "svc-c"]


def test_to_dict_structure() -> None:
    node = _node("svc-a", "/api/v1/users", "team-a", 0.9, repo="repo-a")
    graph = InventoryGraph(nodes=[node])

    payload = graph.to_dict()

    assert isinstance(payload, list)
    assert len(payload) == 1
    assert payload[0]["service"] == "svc-a"
    assert payload[0]["repo"] == "repo-a"
    assert payload[0]["endpoint_pattern"] == "/api/v1/users"
    assert payload[0]["method"] == "GET"
    assert payload[0]["operations"] == ["read"]
    assert payload[0]["owner_team"] == "team-a"
    assert payload[0]["owner_confidence"] == 0.9
    assert payload[0]["finding_ids"] == ["F-1"]
    assert payload[0]["evidence_ids"] == ["E-1"]
    assert payload[0]["source"] == "unknown"


def test_detect_drift_all_categories() -> None:
    graph = InventoryGraph(
        nodes=[
            _node("svc-users", "/api/v1/users", "team-a", 0.95, source="code_extractor"),
            _node("svc-orders", "/api/v1/orders", "team-b", 0.2, source="code_extractor"),
            _node("svc-internal", "/api/v1/internal", "team-c", 0.9, source="code_extractor"),
        ]
    )

    runtime_endpoints = [
        "/api/v1/users",
        "/api/v1/orders",
        "/api/v2/users",
        "/api/v1/payments",
    ]
    code_endpoints = [
        "/api/v1/users",
        "/api/v1/orders",
        "/api/v1/internal",
    ]

    report = detect_drift(graph, runtime_endpoints, code_endpoints)

    assert isinstance(report, DriftReport)
    assert set(report.runtime_no_owner) == {"/api/v1/orders", "/api/v1/payments", "/api/v2/users"}
    assert report.repo_not_deployed == ["/api/v1/internal"]
    assert report.stale_version == ["/api/v1/users"]
