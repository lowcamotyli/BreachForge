from __future__ import annotations

import pytest

from scripts.benchmark_importers import GenericDastImporter, NucleiImporter, SarifImporter, ZapImporter


def test_zap_json_basic() -> None:
    findings = ZapImporter().parse_json(
        {
            "alerts": [
                {
                    "alertRef": "10016",
                    "alert": "XSS",
                    "uri": "/search",
                    "method": "GET",
                    "riskdesc": "High (Confirmed)",
                }
            ]
        }
    )

    assert len(findings) == 1
    assert findings[0].confidence == 0.9
    assert findings[0].source_engine == "zap"


def test_zap_xml_basic() -> None:
    findings = ZapImporter().parse_xml(
        "<OWASPZAPReport><site><alerts><alertitem><alert>SQL Injection</alert>"
        "<uri>/login</uri><riskcode>3</riskcode><method>POST</method></alertitem>"
        "</alerts></site></OWASPZAPReport>"
    )

    assert isinstance(findings, list)


def test_nuclei_jsonl_basic() -> None:
    findings = NucleiImporter().parse_jsonl(
        '{"template-id":"bola-test","info":{"name":"BOLA","severity":"high","tags":["bola"]},'
        '"matched-at":"/users/1","request":{"method":"GET"}}\n'
    )

    assert len(findings) == 1
    assert findings[0].source_engine == "nuclei"
    assert findings[0].confidence == 0.9


def test_sarif_basic() -> None:
    findings = SarifImporter().parse(
        {
            "runs": [
                {
                    "tool": {"driver": {"name": "t", "rules": []}},
                    "results": [
                        {
                            "ruleId": "sql-injection",
                            "message": {"text": "x"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/login"}}}],
                            "level": "error",
                        }
                    ],
                }
            ]
        }
    )

    assert len(findings) == 1


def test_generic_dast_basic() -> None:
    findings = GenericDastImporter().parse(
        {"findings": [{"id": "f1", "type": "BOLA", "url": "/users/1", "severity": "High"}]}
    )

    assert len(findings) == 1
    assert findings[0].category == "BOLA"


def test_unknown_type_flagged() -> None:
    findings = GenericDastImporter().parse({"findings": [{"id": "x", "type": "XYZUNKNOWN99", "url": "/foo"}]})

    assert findings[0].manual_review_flag is True
    assert findings[0].category == "unknown"


def test_empty_input_zap() -> None:
    assert ZapImporter().parse_json({}) == []


def test_empty_input_nuclei() -> None:
    assert NucleiImporter().parse_jsonl("") == []


def test_empty_input_sarif() -> None:
    assert SarifImporter().parse({}) == []


def test_empty_input_generic() -> None:
    assert GenericDastImporter().parse({}) == []


def test_confidence_range() -> None:
    importers = [
        ZapImporter().parse_json({"alerts": [{"alert": "XSS", "uri": "/search", "riskdesc": "High"}]}),
        NucleiImporter().parse_jsonl(
            '{"template-id":"bola-test","info":{"name":"BOLA","severity":"high","tags":["bola"]},'
            '"matched-at":"/users/1","request":{"method":"GET"}}\n'
        ),
        SarifImporter().parse(
            {"runs": [{"tool": {"driver": {"rules": []}}, "results": [{"ruleId": "sql-injection"}]}]}
        ),
        GenericDastImporter().parse({"findings": [{"type": "BOLA", "url": "/users/1", "severity": "High"}]}),
    ]

    for findings in importers:
        assert findings
        assert all(0.0 <= finding.confidence <= 1.0 for finding in findings)


def test_imported_unknown_is_not_known_category() -> None:
    findings = ZapImporter().parse_json({"alerts": [{"alert": "Unmapped Scanner Finding", "uri": "/x"}]})

    assert findings[0].manual_review_flag is True
    assert findings[0].category == "unknown"
