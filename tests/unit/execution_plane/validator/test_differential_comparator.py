from __future__ import annotations

import httpx

from execution_plane.validator.differential import (
    JsonStructuralComparator,
    ResponseComparator,
    TextComparator,
)


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


def test_json_structural_detects_added_key() -> None:
    comparator = JsonStructuralComparator()

    result = comparator.compare(before={"id": 1}, after={"id": 1, "name": "alpha"})

    assert result.added_keys == ["name"]


def test_json_structural_detects_removed_key() -> None:
    comparator = JsonStructuralComparator()

    result = comparator.compare(before={"id": 1, "name": "alpha"}, after={"id": 1})

    assert result.removed_keys == ["name"]


def test_json_structural_detects_type_change() -> None:
    comparator = JsonStructuralComparator()

    result = comparator.compare(before={"id": 1}, after={"id": "1"})

    assert result.type_changed_keys == ["id"]


def test_json_structural_detects_list_length_change() -> None:
    comparator = JsonStructuralComparator()

    result = comparator.compare(before={"items": [1, 2]}, after={"items": [1, 2, 3]})

    assert result.list_length_changes == {"items": (2, 3)}


def test_json_structural_volatile_excluded_from_meaningful_change() -> None:
    comparator = JsonStructuralComparator()

    result = comparator.compare(
        before={"updated_at": "2026-05-13T10:00:00Z"},
        after={"updated_at": "2026-05-13T10:01:00Z"},
    )

    assert result.has_meaningful_change() is False


def test_json_structural_real_change_is_meaningful() -> None:
    comparator = JsonStructuralComparator()

    result = comparator.compare(before={"amount": 100}, after={"amount": 200})

    assert result.has_meaningful_change() is True


def test_text_comparator_same_text_similarity_one() -> None:
    comparator = TextComparator()

    result = comparator.compare(before="same response", after="same response")

    assert result.normalized_similarity == 1.0
    assert result.bucket_changed is False


def test_text_comparator_different_buckets_bucket_changed() -> None:
    comparator = TextComparator()

    result = comparator.compare(before="short", after="x" * 101)

    assert result.length_bucket_before == "tiny"
    assert result.length_bucket_after == "small"
    assert result.bucket_changed is True


def test_text_comparator_empty_is_zero_bucket() -> None:
    comparator = TextComparator()

    result = comparator.compare(before="", after="")

    assert result.length_bucket_before == "0"
    assert result.length_bucket_after == "0"
    assert result.bucket_changed is False
