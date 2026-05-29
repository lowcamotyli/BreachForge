from __future__ import annotations

from typing import Any

import httpx
import pytest

from control_plane.integrations.github import GithubAdapter
from control_plane.integrations.jira import JiraAdapter


class _FakeResponse:
    def __init__(self, payload: dict[str, Any] | None = None) -> None:
        self._payload = payload or {}
        self.raise_for_status_called = False

    def raise_for_status(self) -> None:
        self.raise_for_status_called = True

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeAsyncClient:
    calls: list[dict[str, Any]] = []
    response = _FakeResponse()

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    async def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append({"url": url, **kwargs})
        return self.response


def test_format_evidence_summary_includes_required_fields() -> None:
    finding = {
        "severity": "high",
        "attack_class": "bola",
        "repro_steps": ["Log in as user A", "Request user B resource"],
        "fix_guidance": "Enforce object ownership checks.",
        "safety_label": "confirmed-safe",
        "owner_team": "identity",
        "owner_service": "accounts-api",
        "evidence_summary": "User A can read user B profile.",
    }

    summary = GithubAdapter().format_evidence_summary(finding)

    assert "Severity:** high" in summary
    assert "Attack class:** bola" in summary
    assert "1. Log in as user A" in summary
    assert "2. Request user B resource" in summary
    assert "Fix guidance" in summary
    assert "confirmed-safe" in summary
    assert "identity" in summary
    assert "accounts-api" in summary


@pytest.mark.asyncio
async def test_post_finding_issue_posts_to_correct_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _FakeResponse({"html_url": "https://github.com/acme/app/issues/7"})
    _FakeAsyncClient.calls = []
    _FakeAsyncClient.response = response
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)

    issue_url = await GithubAdapter(api_base="https://api.github.test").post_finding_issue(
        {
            "severity": "critical",
            "attack_class": "ssrf",
            "repro_steps": "Send callback URL to metadata IP.",
            "fix_guidance": "Block link-local egress.",
            "safety_label": "security",
        },
        repo="acme/app",
        token="test-token",
    )

    assert issue_url == "https://github.com/acme/app/issues/7"
    assert response.raise_for_status_called is True
    assert _FakeAsyncClient.calls == [
        {
            "url": "https://api.github.test/repos/acme/app/issues",
            "headers": {
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer test-token",
            },
            "json": {
                "title": "[critical] ssrf security finding",
                "body": GithubAdapter(api_base="https://api.github.test").format_evidence_summary(
                    {
                        "severity": "critical",
                        "attack_class": "ssrf",
                        "repro_steps": "Send callback URL to metadata IP.",
                        "fix_guidance": "Block link-local egress.",
                        "safety_label": "security",
                    }
                ),
                "labels": ["security"],
            },
        }
    ]


@pytest.mark.asyncio
async def test_add_pr_comment_posts_to_pr_comment_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _FakeResponse()
    _FakeAsyncClient.calls = []
    _FakeAsyncClient.response = response
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)

    await GithubAdapter(api_base="https://api.github.test/").add_pr_comment(
        pr_number=42,
        body="Security finding evidence summary",
        repo="acme/app",
        token="test-token",
    )

    assert response.raise_for_status_called is True
    assert _FakeAsyncClient.calls == [
        {
            "url": "https://api.github.test/repos/acme/app/issues/42/comments",
            "headers": {
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer test-token",
            },
            "json": {"body": "Security finding evidence summary"},
        }
    ]


def test_jira_severity_to_priority_maps_expected_values() -> None:
    adapter = JiraAdapter()
    assert adapter.severity_to_priority("critical") == "Highest"
    assert adapter.severity_to_priority("high") == "High"
    assert adapter.severity_to_priority("medium") == "Medium"
    assert adapter.severity_to_priority("info") == "Low"
    assert adapter.severity_to_priority("unknown") == "Medium"


def test_jira_format_description_includes_attack_class_and_fix_guidance() -> None:
    description = JiraAdapter().format_description(
        {
            "attack_class": "idor",
            "severity": "high",
            "fix_guidance": "Apply row-level authorization checks.",
            "repro_steps": "Call endpoint with another user ID.",
        }
    )
    assert "Attack class: idor" in description
    assert "## Fix Guidance" in description
    assert "Apply row-level authorization checks." in description


@pytest.mark.asyncio
async def test_jira_create_issue_posts_to_correct_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _FakeResponse({"key": "PROJ-123"})
    _FakeAsyncClient.calls = []
    _FakeAsyncClient.response = response
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)

    issue_key = await JiraAdapter().create_issue(
        finding={
            "title": "SSRF finding",
            "severity": "critical",
            "attack_class": "ssrf",
            "repro_steps": "Send URL to metadata IP.",
            "fix_guidance": "Block link-local egress.",
            "proof_hash": "abc123",
        },
        project_key="PROJ",
        jira_url="https://jira.example.com/",
        token="base64-email-token",
    )

    assert issue_key == "PROJ-123"
    assert response.raise_for_status_called is True
    assert _FakeAsyncClient.calls[0]["url"] == "https://jira.example.com/rest/api/2/issue"
