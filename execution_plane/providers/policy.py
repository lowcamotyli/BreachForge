from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from urllib.parse import urlparse

from api.models.requests import ScanPolicy


PRIVATE_RANGES: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


@dataclass
class NetworkScopePolicy:
    allowed_hosts: list[str]
    localhost_benchmark_mode: bool = False

    def is_target_allowed(self, target_url: str) -> bool:
        host = _hostname_from_url(target_url)
        if host is None:
            return False

        if _is_private_target(host) and not self.localhost_benchmark_mode:
            return False

        if self.allowed_hosts:
            return _normalize_host(host) in {
                _normalize_host(allowed_host) for allowed_host in self.allowed_hosts
            }

        return True

    @classmethod
    def from_scan_policy(cls, policy: ScanPolicy) -> NetworkScopePolicy:
        return cls(
            allowed_hosts=list(getattr(policy, "allowed_hosts", []) or []),
            localhost_benchmark_mode=bool(
                getattr(policy, "localhost_benchmark_mode", False)
            ),
        )


def _hostname_from_url(target_url: str) -> str | None:
    parsed = urlparse(target_url)
    return parsed.hostname


def _is_private_target(host: str) -> bool:
    normalized_host = _normalize_host(host)
    if normalized_host == "localhost":
        return True

    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        return False

    return any(address in private_range for private_range in PRIVATE_RANGES)


def _normalize_host(host: str) -> str:
    parsed_host = urlparse(host).hostname if "://" in host else host
    return (parsed_host or host).rstrip(".").lower()
