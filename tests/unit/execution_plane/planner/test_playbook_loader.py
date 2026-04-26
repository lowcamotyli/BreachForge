from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from execution_plane.planner.playbook_loader import load_playbook
from execution_plane.planner.playbooks import PlaybookValidationError


def _playbook_payload() -> dict[str, object]:
    return {
        "id": "loader_sample",
        "attack_class": "bola",
        "preconditions": {"methods": ["GET"]},
        "steps": [
            {
                "id": "step_a",
                "action": "discover",
                "identity_selector": "current_user",
                "probe_template": {"mode": "observe", "variables": {"hint": "id"}},
                "expected_signal": "signal",
                "validator": "v1",
                "max_attempts": 1,
            }
        ],
        "validators": {"v1": {"signal": "ok"}},
        "safety_budget": {
            "max_requests": 1,
            "max_attempts_per_step": 1,
            "rate_limit_rps": 1.0,
            "scope": "current_endpoint",
            "proof_gate": "default",
        },
    }


def test_load_playbook_accepts_json_file(tmp_path: Path) -> None:
    path = tmp_path / "loader_sample.json"
    path.write_text(json.dumps(_playbook_payload()), encoding="utf-8")

    playbook = load_playbook(path)

    assert playbook.id == "loader_sample"


def test_load_playbook_yaml_fallback_when_available(tmp_path: Path) -> None:
    path = tmp_path / "loader_sample.yaml"
    path.write_text(
        "\n".join(
            [
                "id: loader_yaml",
                "attack_class: bola",
                "preconditions:",
                "  methods: [GET]",
                "steps:",
                "  - id: step_a",
                "    action: discover",
                "    identity_selector: current_user",
                "    probe_template:",
                "      mode: observe",
                "      variables:",
                "        hint: id",
                "    expected_signal: signal",
                "    validator: v1",
                "    max_attempts: 1",
                "validators:",
                "  v1:",
                "    signal: ok",
                "safety_budget:",
                "  max_requests: 1",
                "  max_attempts_per_step: 1",
                "  rate_limit_rps: 1.0",
                "  scope: current_endpoint",
                "  proof_gate: default",
            ]
        ),
        encoding="utf-8",
    )

    try:
        import yaml  # noqa: F401
    except Exception:
        with pytest.raises(PlaybookValidationError):
            load_playbook(path)
        return

    playbook = load_playbook(path)
    assert playbook.id == "loader_yaml"


def test_load_playbook_rejects_malformed_payload(tmp_path: Path) -> None:
    malformed = tmp_path / "broken.yaml"
    malformed.write_text("{not valid", encoding="utf-8")

    with pytest.raises(PlaybookValidationError, match="malformed playbook"):
        load_playbook(malformed)
