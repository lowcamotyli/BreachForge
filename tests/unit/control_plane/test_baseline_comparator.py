from __future__ import annotations

from control_plane.baseline_comparator import compare


def test_new_finding() -> None:
    baseline: list[dict] = []
    finding = {"attack_class": "xss", "target_url": "https://app.example.com/a", "severity": "high"}
    current = [finding]
    result = compare(baseline=baseline, current=current)
    assert result.new == [finding]
    assert result.fixed == []
    assert result.unchanged == []


def test_fixed_finding() -> None:
    finding = {"attack_class": "sqli", "target_url": "https://app.example.com/b", "severity": "critical"}
    baseline = [finding]
    current: list[dict] = []
    result = compare(baseline=baseline, current=current)
    assert result.new == []
    assert result.fixed == [finding]
    assert result.unchanged == []


def test_unchanged() -> None:
    baseline_finding = {"attack_class": "bola", "target_url": "https://app.example.com/c", "severity": "high"}
    current_finding = {"attack_class": "bola", "target_url": "https://app.example.com/c", "severity": "medium"}
    result = compare(baseline=[baseline_finding], current=[current_finding])
    assert result.new == []
    assert result.fixed == []
    assert result.unchanged == [current_finding]


def test_empty_baseline() -> None:
    current = [
        {"attack_class": "idor", "target_url": "https://app.example.com/d", "severity": "high"},
        {"attack_class": "ssrf", "target_url": "https://app.example.com/e", "severity": "medium"},
    ]
    result = compare(baseline=[], current=current)
    assert result.new == current
    assert result.fixed == []
    assert result.unchanged == []


def test_summary_counts() -> None:
    baseline = [
        {"attack_class": "xss", "target_url": "https://app.example.com/a", "severity": "high"},
        {"attack_class": "sqli", "target_url": "https://app.example.com/b", "severity": "critical"},
    ]
    current = [
        {"attack_class": "xss", "target_url": "https://app.example.com/a", "severity": "high"},
        {"attack_class": "csrf", "target_url": "https://app.example.com/c", "severity": "medium"},
    ]
    result = compare(baseline=baseline, current=current)
    assert result.summary == {"new": 1, "fixed": 1, "unchanged": 1, "total": 3}
