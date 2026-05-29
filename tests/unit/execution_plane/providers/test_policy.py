from __future__ import annotations

from execution_plane.providers.policy import NetworkScopePolicy


def test_private_10_range_is_denied() -> None:
    policy = NetworkScopePolicy(allowed_hosts=[])

    assert policy.is_target_allowed("http://10.0.0.1") is False


def test_loopback_is_denied_unless_localhost_benchmark_mode() -> None:
    default_policy = NetworkScopePolicy(allowed_hosts=[])
    benchmark_policy = NetworkScopePolicy(
        allowed_hosts=[], localhost_benchmark_mode=True
    )

    assert default_policy.is_target_allowed("http://127.0.0.1") is False
    assert benchmark_policy.is_target_allowed("http://127.0.0.1") is True


def test_external_host_allowed_when_in_allowed_hosts() -> None:
    policy = NetworkScopePolicy(allowed_hosts=["example.com"])

    assert policy.is_target_allowed("https://example.com") is True


def test_external_host_denied_when_allowed_hosts_is_non_empty_and_host_missing() -> None:
    policy = NetworkScopePolicy(allowed_hosts=["example.com"])

    assert policy.is_target_allowed("https://not-example.com") is False


def test_scope_escape_subdomain_is_denied() -> None:
    policy = NetworkScopePolicy(allowed_hosts=["example.com"])

    assert policy.is_target_allowed("https://example.com.evil.test") is False
