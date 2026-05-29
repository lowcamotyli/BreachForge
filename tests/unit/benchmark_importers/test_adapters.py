from __future__ import annotations

from scripts.benchmark_importers.hexstrike import HexStrikeImporter
from scripts.benchmark_importers.nuclei_adapter import NucleiImporter
from scripts.benchmark_importers.sarif import SarifImporter


def test_hexstrike_normalize() -> None:
    raw = [
        {"id": "h-1", "title": "SQL Injection", "severity": "critical", "endpoint": "/login", "evidence": "x"},
        {"id": "h-2", "title": "BOLA", "severity": "low", "endpoint": "/users/1", "evidence": "y"},
    ]
    findings = HexStrikeImporter().normalize(raw)

    assert len(findings) == 2
    assert all(set(("id", "attack_class", "endpoint", "severity", "confidence", "engine", "raw")).issubset(f) for f in findings)
    assert findings[0]["severity"] == "HIGH"
    assert findings[1]["severity"] == "LOW"


def test_nuclei_normalize() -> None:
    raw = [
        {
            "template-id": "bola-basic",
            "severity": "medium",
            "host": "https://app.example.com",
            "matched-at": "https://app.example.com/users/1",
            "info": {"name": "bola-check"},
        },
        {
            "template-id": "xss-basic",
            "severity": "high",
            "host": "https://app.example.com",
            "matched-at": "https://app.example.com/search",
            "info": {"name": "reflected-xss"},
        },
    ]
    findings = NucleiImporter().normalize(raw)

    assert len(findings) == 2
    assert all(set(("id", "attack_class", "endpoint", "severity", "confidence", "engine", "raw")).issubset(f) for f in findings)
    assert findings[0]["id"] == "bola-basic"
    assert findings[0]["engine"] == "nuclei"


def test_nuclei_parse_jsonl() -> None:
    text = "\n".join(
        [
            '{"template-id":"a","matched-at":"/a","info":{"name":"bola"}}',
            '{"template-id":"b","matched-at":"/b","info":{"name":"xss"}}',
            '{"template-id":"c","matched-at":"/c","info":{"name":"sqli"}}',
        ]
    )

    parsed = NucleiImporter().parse_jsonl(text)
    assert len(parsed) == 3
    assert all(isinstance(item, dict) for item in parsed)


def test_sarif_still_works() -> None:
    importer = SarifImporter()
    assert callable(getattr(importer, "parse", None))
