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


class CouponStackingRule(AttackRule):
    requires_auth = True
    safe_mutation = True
    name: str = "CouponStackingRule"
    attack_class: str = "coupon_stacking"
    _TOKENS: frozenset[str] = frozenset({"coupon", "discount", "promo", "cart", "checkout"})

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        method: str = endpoint.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return False
        haystack: str = f"{endpoint.url_pattern} {getattr(endpoint, 'example_request_body', '')}".lower()
        return any(token in haystack for token in self._TOKENS)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="coupon_code",
                hypothesis=(
                    "Apply identical coupon_code multiple times on cart endpoint; expect single discount only, "
                    "but repeated application may stack unexpectedly."
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="coupon_code",
                hypothesis=(
                    "Apply mixed discount codes in sequence on checkout/cart flow; validate whether cumulative "
                    "discount bypasses intended pricing floor."
                ),
            ),
        ]

    def expected_proof_signal(self) -> str:
        return "Same or chained coupon codes applied multiple times causing cumulative discount"


class NegativeQuantityRule(AttackRule):
    requires_auth = True
    safe_mutation = True
    name: str = "NegativeQuantityRule"
    attack_class: str = "negative_quantity"
    _TOKENS: frozenset[str] = frozenset({"cart", "order", "checkout", "quantity", "qty", "items"})

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        method: str = endpoint.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return False
        haystack: str = f"{endpoint.url_pattern} {getattr(endpoint, 'example_request_body', '')}".lower()
        return any(token in haystack for token in self._TOKENS)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        probes: tuple[str, ...] = ("-1", "-99", "0")
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="qty",
                hypothesis=(
                    f"Submit qty={probe} to cart/order endpoint; validate if total decreases or becomes negative "
                    "instead of being rejected."
                ),
            )
            for probe in probes
        ]

    def expected_proof_signal(self) -> str:
        return "Negative or zero quantity accepted and total amount decreases below expected boundary"


class PriceTamperingRule(AttackRule):
    requires_auth = True
    safe_mutation = True
    name: str = "PriceTamperingRule"
    attack_class: str = "price_tampering"
    _TOKENS: frozenset[str] = frozenset({"price", "amount", "total", "cart", "order", "checkout"})

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        method: str = endpoint.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return False
        haystack: str = f"{endpoint.url_pattern} {getattr(endpoint, 'example_request_body', '')}".lower()
        return any(token in haystack for token in self._TOKENS)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="price",
                hypothesis=(
                    "Tamper mutable price/amount field in request body to 0.01 and validate whether final state "
                    "price diverges from original authoritative price."
                ),
            ),
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="price",
                hypothesis=(
                    "Tamper mutable price/amount field in request body to -1 and validate whether server accepts "
                    "negative pricing in persisted order/cart state."
                ),
            ),
        ]

    def expected_proof_signal(self) -> str:
        return "Final persisted price reflects attacker-supplied tampered amount instead of server-side original"


class InventoryReservationAbuseRule(AttackRule):
    requires_auth = True
    observe_only = True
    name: str = "InventoryReservationAbuseRule"
    attack_class: str = "inventory_reservation_abuse"
    _TOKENS: frozenset[str] = frozenset({"reserve", "reservation", "hold", "inventory", "stock", "cart"})

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        method: str = endpoint.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return False
        haystack: str = f"{endpoint.url_pattern} {getattr(endpoint, 'example_request_body', '')}".lower()
        return any(token in haystack for token in self._TOKENS)

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        return [
            AttackTask(
                scan_id=context.scan_id,
                endpoint_id=endpoint.id,
                attack_class=self.attack_class,
                target_parameter="reservation_hold",
                hypothesis=(
                    "Reserve or hold inventory without completing purchase; observe if inventory counter remains "
                    "decremented without corresponding paid order event."
                ),
            )
        ]

    def expected_proof_signal(self) -> str:
        return "Inventory count remains decremented after hold/reservation flow without completed payment"
