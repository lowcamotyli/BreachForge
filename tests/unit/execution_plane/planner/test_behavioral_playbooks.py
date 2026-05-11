from __future__ import annotations

from execution_plane.planner.playbook_loader import load_builtin_playbooks
from execution_plane.planner.playbooks import AttackPlaybook


BEHAVIORAL_PLAYBOOK_IDS = {
    "step_skipping",
    "replay_state_change",
    "race_conditions",
    "cache_auth_drift",
    "forced_browsing",
}


def _playbooks_by_id() -> dict[str, AttackPlaybook]:
    return {playbook.id: playbook for playbook in load_builtin_playbooks()}


def test_step_skipping_loads() -> None:
    playbook = _playbooks_by_id()["step_skipping"]

    assert playbook.attack_class == "workflow_abuse"


def test_replay_state_change_loads() -> None:
    playbook = _playbooks_by_id()["replay_state_change"]

    assert playbook.attack_class == "workflow_abuse"


def test_race_conditions_loads() -> None:
    playbook = _playbooks_by_id()["race_conditions"]

    assert playbook.attack_class == "race_condition"


def test_cache_auth_drift_loads() -> None:
    playbook = _playbooks_by_id()["cache_auth_drift"]

    assert playbook.attack_class == "sensitive_exposure"


def test_forced_browsing_loads() -> None:
    playbook = _playbooks_by_id()["forced_browsing"]

    assert playbook.attack_class == "sensitive_exposure"


def test_all_behavioral_playbooks_are_read_only() -> None:
    playbooks = _playbooks_by_id()

    for playbook_id in BEHAVIORAL_PLAYBOOK_IDS:
        playbook = playbooks[playbook_id]
        assert all(step.observe_only is True for step in playbook.steps)


def test_race_conditions_has_reproducibility_required() -> None:
    playbook = _playbooks_by_id()["race_conditions"]

    assert "reproducibility_required" in playbook.validators or "burst_concurrency" in playbook.safety_budget
