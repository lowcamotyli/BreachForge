from __future__ import annotations

from control_plane.integrations.github import GithubAdapter


def test_pr_comment_with_new_findings() -> None:
    adapter = GithubAdapter()
    new_findings = [
        {
            "id": "finding-1",
            "severity": "high",
            "attack_class": "ssrf",
            "owner_team": "platform-security",
            "confidence_score": 0.92,
            "target_url": "https://app.example.com/admin",
        },
        {
            "id": "finding-2",
            "severity": "medium",
            "attack_class": "csrf",
            "owner_service": "checkout",
            "confidence_score": 0.81,
            "target_url": "https://app.example.com/cart",
        },
    ]

    body = adapter.format_pr_scan_summary(
        scan_id="scan-123",
        target_url="https://app.example.com",
        api_url="https://api.breachforge.io",
        new_findings=new_findings,
        fixed_count=1,
        unchanged_count=3,
    )

    assert "#### [high] ssrf" in body
    assert "#### [medium] csrf" in body
    assert "- **Owner:** platform-security" in body
    assert "- **Owner:** checkout" in body
    assert "breachforge scan run --target https://app.example.com/admin" in body
    assert "https://api.breachforge.io/api/findings/finding-1/suppress" in body


def test_pr_comment_no_new_findings() -> None:
    adapter = GithubAdapter()

    body = adapter.format_pr_scan_summary(
        scan_id="scan-456",
        target_url="https://app.example.com",
        api_url="https://api.breachforge.io",
        new_findings=[],
        fixed_count=2,
        unchanged_count=4,
    )

    assert "No new security findings" in body


def test_pr_comment_contains_scan_id() -> None:
    adapter = GithubAdapter()

    body = adapter.format_pr_scan_summary(
        scan_id="scan-xyz",
        target_url="https://app.example.com",
        api_url="https://api.breachforge.io",
        new_findings=[],
        fixed_count=0,
        unchanged_count=0,
    )

    assert "scan-xyz" in body


def test_pr_comment_suppress_url_format() -> None:
    adapter = GithubAdapter()
    new_findings = [
        {
            "id": "finding-99",
            "severity": "low",
            "attack_class": "misconfiguration",
            "target_url": "https://app.example.com/settings",
        }
    ]

    body = adapter.format_pr_scan_summary(
        scan_id="scan-999",
        target_url="https://app.example.com",
        api_url="https://api.breachforge.io/",
        new_findings=new_findings,
        fixed_count=0,
        unchanged_count=1,
    )

    assert "https://api.breachforge.io/api/findings/finding-99/suppress" in body
