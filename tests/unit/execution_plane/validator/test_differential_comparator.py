from __future__ import annotations

import httpx

from execution_plane.validator.differential import ResponseComparator


def test_same_status_same_json_shape() -> None:
    comparator = ResponseComparator()
    baseline = httpx.Response(200, json={"id": 1, "name": "alpha"})
    challenger = httpx.Response(200, json={"id": 2, "name": "beta"})

    result = comparator.compare(
        baseline_resp=baseline,
        challenger_resp=challenger,
        baseline_identity="owner",
        challenger_identity="attacker",
    )

    assert result.status_differs is False
    assert result.shape_differs is False


def test_different_status_codes_sets_status_differs() -> None:
    comparator = ResponseComparator()
    baseline = httpx.Response(200, json={"id": 1})
    challenger = httpx.Response(403, json={"id": 1})

    result = comparator.compare(
        baseline_resp=baseline,
        challenger_resp=challenger,
        baseline_identity="owner",
        challenger_identity="attacker",
    )

    assert result.status_differs is True


def test_different_top_level_key_sets_sets_shape_differs() -> None:
    comparator = ResponseComparator()
    baseline = httpx.Response(200, json={"id": 1, "name": "alpha"})
    challenger = httpx.Response(200, json={"id": 1, "email": "a@example.test"})

    result = comparator.compare(
        baseline_resp=baseline,
        challenger_resp=challenger,
        baseline_identity="owner",
        challenger_identity="attacker",
    )

    assert result.shape_differs is True


def test_different_owner_id_sets_ownership_markers_differ() -> None:
    comparator = ResponseComparator()
    baseline = httpx.Response(200, json={"owner_id": 10, "resource": "x"})
    challenger = httpx.Response(200, json={"owner_id": 99, "resource": "x"})

    result = comparator.compare(
        baseline_resp=baseline,
        challenger_resp=challenger,
        baseline_identity="owner",
        challenger_identity="attacker",
    )

    assert result.ownership_markers_differ is True
