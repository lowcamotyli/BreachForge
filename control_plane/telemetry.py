from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4


class MetricType(StrEnum):
    performance = "performance"
    error = "error"
    coverage = "coverage"
    runner_health = "runner_health"


@dataclass
class TelemetryEvent:
    event_id: UUID = field(default_factory=uuid4)
    org_id: UUID = field(default_factory=uuid4)
    metric_type: MetricType = MetricType.performance
    name: str = ""
    value: float = 0.0
    unit: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    tags: dict[str, str] = field(default_factory=dict)
    # NEVER include: request bodies, auth headers, tokens, secrets

    def has_sensitive_data(self) -> bool:
        """Returns True if any tag key/value looks like a secret."""
        sensitive_keys = {"authorization", "cookie", "password", "token", "secret", "key", "credential"}
        for key, value in self.tags.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                return True
            if any(sensitive in value.lower() for sensitive in {"bearer ", "basic ", "eyj"}):
                return True
        return False


class TelemetryCollector:
    """Minimal in-memory telemetry collector. Strips sensitive data on record."""

    def __init__(self) -> None:
        self._events: list[TelemetryEvent] = []

    def record(self, event: TelemetryEvent) -> bool:
        """Returns False and drops event if it contains sensitive data."""
        if event.has_sensitive_data():
            return False
        self._events.append(event)
        return True

    def record_scan_performance(
        self,
        org_id: UUID,
        scan_id: UUID,
        duration_seconds: float,
        endpoints_tested: int,
    ) -> TelemetryEvent:
        event = TelemetryEvent(
            org_id=org_id,
            metric_type=MetricType.performance,
            name="scan.duration_seconds",
            value=duration_seconds,
            unit="seconds",
            tags={"scan_id": str(scan_id), "endpoints_tested": str(endpoints_tested)},
        )
        self.record(event)
        return event

    def record_error(self, org_id: UUID, error_class: str, component: str) -> TelemetryEvent:
        event = TelemetryEvent(
            org_id=org_id,
            metric_type=MetricType.error,
            name="error.count",
            value=1.0,
            unit="count",
            tags={"error_class": error_class, "component": component},
        )
        self.record(event)
        return event

    def record_coverage(
        self,
        org_id: UUID,
        scan_id: UUID,
        coverage_pct: float,
        total_endpoints: int,
    ) -> TelemetryEvent:
        event = TelemetryEvent(
            org_id=org_id,
            metric_type=MetricType.coverage,
            name="scan.coverage_pct",
            value=coverage_pct,
            unit="percent",
            tags={"scan_id": str(scan_id), "total_endpoints": str(total_endpoints)},
        )
        self.record(event)
        return event

    def record_runner_health(
        self,
        org_id: UUID,
        runner_id: UUID,
        is_healthy: bool,
        response_ms: float,
    ) -> TelemetryEvent:
        event = TelemetryEvent(
            org_id=org_id,
            metric_type=MetricType.runner_health,
            name="runner.health",
            value=1.0 if is_healthy else 0.0,
            unit="bool",
            tags={"runner_id": str(runner_id), "response_ms": str(round(response_ms, 2))},
        )
        self.record(event)
        return event

    def get_events(
        self,
        org_id: UUID | None = None,
        metric_type: MetricType | None = None,
    ) -> list[TelemetryEvent]:
        result = self._events
        if org_id is not None:
            result = [event for event in result if event.org_id == org_id]
        if metric_type is not None:
            result = [event for event in result if event.metric_type == metric_type]
        return result

    def flush(self) -> list[TelemetryEvent]:
        events = list(self._events)
        self._events.clear()
        return events
