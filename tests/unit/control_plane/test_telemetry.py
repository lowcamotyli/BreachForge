from __future__ import annotations

from uuid import uuid4

from control_plane.telemetry import MetricType, TelemetryCollector, TelemetryEvent


def test_record_adds_event_to_collector() -> None:
    collector = TelemetryCollector()
    event = TelemetryEvent(name="scan.started")

    assert collector.record(event) is True

    assert collector.get_events() == [event]


def test_record_returns_false_and_drops_event_when_has_sensitive_data() -> None:
    collector = TelemetryCollector()
    event = TelemetryEvent(tags={"access_token": "redacted"})

    assert collector.record(event) is False

    assert collector.get_events() == []


def test_record_scan_performance_creates_event_with_correct_metric_type_and_value() -> None:
    collector = TelemetryCollector()
    org_id = uuid4()

    event = collector.record_scan_performance(org_id, uuid4(), 12.5, 42)

    assert event.metric_type == MetricType.performance
    assert event.name == "scan.duration_seconds"
    assert event.value == 12.5
    assert event.unit == "seconds"
    assert collector.get_events() == [event]


def test_record_error_creates_error_event() -> None:
    collector = TelemetryCollector()
    org_id = uuid4()

    event = collector.record_error(org_id, "ValueError", "planner")

    assert event.metric_type == MetricType.error
    assert event.name == "error.count"
    assert event.value == 1.0
    assert event.tags == {"error_class": "ValueError", "component": "planner"}


def test_record_coverage_creates_coverage_event() -> None:
    collector = TelemetryCollector()
    org_id = uuid4()
    scan_id = uuid4()

    event = collector.record_coverage(org_id, scan_id, 87.5, 120)

    assert event.metric_type == MetricType.coverage
    assert event.name == "scan.coverage_pct"
    assert event.value == 87.5
    assert event.tags == {"scan_id": str(scan_id), "total_endpoints": "120"}


def test_record_runner_health_creates_runner_health_event_with_healthy_and_unhealthy_values() -> None:
    collector = TelemetryCollector()
    org_id = uuid4()

    healthy = collector.record_runner_health(org_id, uuid4(), True, 42.126)
    unhealthy = collector.record_runner_health(org_id, uuid4(), False, 500.0)

    assert healthy.metric_type == MetricType.runner_health
    assert healthy.value == 1.0
    assert healthy.tags["response_ms"] == "42.13"
    assert unhealthy.metric_type == MetricType.runner_health
    assert unhealthy.value == 0.0


def test_get_events_filters_by_org_id() -> None:
    collector = TelemetryCollector()
    org_id = uuid4()
    other_org_id = uuid4()
    retained = TelemetryEvent(org_id=org_id)
    collector.record(retained)
    collector.record(TelemetryEvent(org_id=other_org_id))

    assert collector.get_events(org_id=org_id) == [retained]


def test_get_events_filters_by_metric_type() -> None:
    collector = TelemetryCollector()
    retained = TelemetryEvent(metric_type=MetricType.coverage)
    collector.record(TelemetryEvent(metric_type=MetricType.performance))
    collector.record(retained)

    assert collector.get_events(metric_type=MetricType.coverage) == [retained]


def test_flush_clears_internal_list_and_returns_events() -> None:
    collector = TelemetryCollector()
    event = TelemetryEvent(name="scan.finished")
    collector.record(event)

    assert collector.flush() == [event]
    assert collector.get_events() == []
