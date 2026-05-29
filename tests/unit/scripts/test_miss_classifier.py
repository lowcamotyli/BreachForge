from __future__ import annotations

from scripts.benchmark_importers.miss_classifier import MissClassifier, MissStage


def test_classify_crawler_miss() -> None:
    vuln = {"type": "BOLA", "endpoint": "/users/999"}
    scan_result = {"discovered_endpoints": ["/orders", "/profile"], "auth_health_rate": 1.0}
    assert MissClassifier.classify(vuln, scan_result) == MissStage.CRAWLER.value


def test_classify_auth_miss() -> None:
    vuln = {"type": "BOLA", "endpoint": "/users/999"}
    scan_result = {"discovered_endpoints": ["/users/{id}"], "auth_health_rate": 0.2}
    assert MissClassifier.classify(vuln, scan_result) == MissStage.AUTH.value


def test_classify_validator_default() -> None:
    vuln = {"type": "BOLA", "endpoint": "/users/999"}
    scan_result = {}
    assert MissClassifier.classify(vuln, scan_result) == MissStage.VALIDATOR.value


def test_classify_unsupported_class() -> None:
    vuln = {"type": "GRAPHQL_BATCHING", "endpoint": "/graphql"}
    scan_result = {}
    assert MissClassifier.classify(vuln, scan_result, engine="zap") == MissStage.UNSUPPORTED_CLASS.value


def test_annotate_fn_list_empty_when_all_covered() -> None:
    vulns = [{"type": "BOLA", "endpoint": "/users/{id}"}]
    findings = [{"type": "BOLA", "endpoint": "/users/{id}"}]
    result = MissClassifier.annotate_fn_list(vulns, findings, {})
    assert result == []


def test_annotate_fn_list_has_stage() -> None:
    vulns = [{"type": "BOLA", "endpoint": "/users/{id}"}, {"type": "BFLA", "endpoint": "/admin/approve"}]
    findings = [{"type": "BOLA", "endpoint": "/users/{id}"}]
    result = MissClassifier.annotate_fn_list(vulns, findings, {})
    assert len(result) == 1
    assert "missing_detection_stage" in result[0]
    assert result[0]["missing_detection_stage"] in [s.value for s in MissStage]
