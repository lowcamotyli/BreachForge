from __future__ import annotations

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint


class NumericManipulation(AttackRule):
    requires_auth = True
    name: str = "NumericManipulation"
    attack_class: str = "negative_value"
    _NUMERIC_TOKENS: frozenset[str] = frozenset(
        {"price", "amount", "quantity", "balance", "credits", "discount", "fee", "cost", "total", "sum"}
    )

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        method: str = endpoint.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return False

        haystack: str = self._combined_haystack(endpoint)
        return any(token in haystack for token in self._NUMERIC_TOKENS)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        tokens: list[str] = self._extract_tokens(endpoint)[:2]
        tasks: list[AttackTask] = []

        for token in tokens:
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class="negative_value",
                    target_parameter=token,
                    hypothesis=(
                        "Probe numeric param with negative values: -1, -99999, -0.01 — expect rejection "
                        "but may accept if no server-side validation"
                    ),
                )
            )
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class="integer_overflow",
                    target_parameter=token,
                    hypothesis=(
                        "Probe numeric param with overflow values: 2147483648, 9223372036854775807 — "
                        "expect type error or wrapping behavior"
                    ),
                )
            )
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class="price_manipulation",
                    target_parameter=token,
                    hypothesis=(
                        "Probe price/amount param with unit confusion: 0.01 vs 1.00 (cents vs dollars) "
                        "or currency swap USD to JPY"
                    ),
                )
            )

        return tasks

    def expected_proof_signal(self) -> str:
        return "Numeric param accepted invalid value: negative, overflow, or wrong unit"

    def _combined_haystack(self, endpoint: Endpoint) -> str:
        url: str = endpoint.url_pattern.lower()
        body: str = str(getattr(endpoint, "example_request_body", "") or "").lower()
        return f"{url} {body}"

    def _extract_tokens(self, endpoint: Endpoint) -> list[str]:
        haystack: str = self._combined_haystack(endpoint)
        return [token for token in self._NUMERIC_TOKENS if token in haystack]


class AccountEnumeration(AttackRule):
    requires_auth = True
    name: str = "AccountEnumeration"
    attack_class: str = "account_enumeration_timing"
    _AUTH_TOKENS: frozenset[str] = frozenset(
        {
            "/login",
            "/register",
            "/forgot-password",
            "/forgot_password",
            "/check-email",
            "/check_email",
            "/reset-password",
            "/reset_password",
            "/check-username",
        }
    )

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        path: str = endpoint.url_pattern.lower()
        return any(token in path for token in self._AUTH_TOKENS)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="username_or_email",
                hypothesis=(
                    "Timing oracle: measure response time differential for existing vs non-existing "
                    f"identifiers on {endpoint.url_pattern}. Requires 10+ probe pairs and statistical "
                    "analysis (>2 sigma delta)."
                ),
            )
        ]

    def expected_proof_signal(self) -> str:
        return "Statistically significant timing differential between existing and non-existing account lookups"


class InventoryReservation(AttackRule):
    requires_auth = True
    name: str = "InventoryReservation"
    attack_class: str = "inventory_reservation"
    _RESERVATION_TOKENS: frozenset[str] = frozenset({"reserve", "hold", "book", "cart"})

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        method: str = endpoint.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return False

        path: str = endpoint.url_pattern.lower()
        return any(token in path for token in self._RESERVATION_TOKENS)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="inventory_item",
                hypothesis=(
                    f"Cyclic reservation exploit on {endpoint.url_pattern}: reserve -> confirm_hold -> "
                    "cancel -> re-reserve without inventory decrement. Max 3 cycles."
                ),
            )
        ]

    def expected_proof_signal(self) -> str:
        return "Item reserved multiple cycles without inventory count decrement"
