from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from urllib.parse import urlparse

from api.models.requests import ScanPolicyV2
from execution_plane.policy.action_classifier import classify, is_allowed_by_policy


@dataclass
class WillSkip:
    path: str
    method: str
    reason: str


@dataclass
class WillBlock:
    path: str
    method: str
    reason: str


@dataclass
class PolicyPreflight:
    will_test: list[dict] = field(default_factory=list)
    will_skip: list[WillSkip] = field(default_factory=list)
    will_block: list[WillBlock] = field(default_factory=list)

    @classmethod
    def compute(cls, policy: ScanPolicyV2, endpoints: list[dict]) -> PolicyPreflight:
        result = cls()
        for ep in endpoints:
            method = ep.get("method", "GET")
            path = ep.get("path", "/")

            if policy.scope.allowed_domains:
                parsed = urlparse(path if path.startswith("http") else f"http://example.com{path}")
                if parsed.netloc and not any(domain in parsed.netloc for domain in policy.scope.allowed_domains):
                    result.will_block.append(WillBlock(path=path, method=method, reason="out_of_scope"))
                    continue

            blocked_by_pattern = False
            for pattern in policy.scope.denied_path_patterns:
                if fnmatch.fnmatch(path, pattern) or pattern in path:
                    result.will_block.append(WillBlock(path=path, method=method, reason="denied_path"))
                    blocked_by_pattern = True
                    break
            if blocked_by_pattern:
                continue

            action = classify(method, path)
            if not is_allowed_by_policy(action, policy):
                result.will_block.append(
                    WillBlock(path=path, method=method, reason=f"method_not_allowed:{action.value}")
                )
                continue

            result.will_test.append(ep)
        return result
