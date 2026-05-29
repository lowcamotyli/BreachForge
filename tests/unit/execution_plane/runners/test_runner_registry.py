from __future__ import annotations

from uuid import uuid4

from execution_plane.runners.registry import RunnerCapabilities, RunnerRegistration, RunnerRegistry


def test_register_returns_runner_registration_and_plaintext_token() -> None:
    registry = RunnerRegistry()
    org_id = uuid4()

    registration, token = registry.register(org_id, "private-runner", RunnerCapabilities(attack_classes=["bola"]))

    assert isinstance(registration, RunnerRegistration)
    assert registration.org_id == org_id
    assert registration.name == "private-runner"
    assert registration.capabilities.attack_classes == ["bola"]
    assert token
    assert registration.token_prefix == token[:8] + "..."
    assert registration.token_hash != token
    assert registration.is_online is True
    assert registration.last_heartbeat_at is not None


def test_heartbeat_updates_last_heartbeat_at() -> None:
    registry = RunnerRegistry()
    registration, _ = registry.register(uuid4(), "private-runner", RunnerCapabilities())
    original_heartbeat = registration.last_heartbeat_at
    current_job_id = uuid4()

    ok = registry.heartbeat(registration.runner_id, current_job_id)

    assert ok is True
    assert registration.last_heartbeat_at is not None
    assert original_heartbeat is not None
    assert registration.last_heartbeat_at >= original_heartbeat
    assert registration.current_job_id == current_job_id
    assert registration.is_online is True


def test_authenticate_token_returns_correct_runner_registration_for_valid_token() -> None:
    registry = RunnerRegistry()
    registration, token = registry.register(uuid4(), "private-runner", RunnerCapabilities())

    authenticated = registry.authenticate_token(token)

    assert authenticated == registration


def test_authenticate_token_returns_none_for_invalid_token() -> None:
    registry = RunnerRegistry()
    registry.register(uuid4(), "private-runner", RunnerCapabilities())

    assert registry.authenticate_token("invalid-token") is None


def test_list_for_org_filters_by_org_id() -> None:
    registry = RunnerRegistry()
    org_id = uuid4()
    other_org_id = uuid4()
    registration, _ = registry.register(org_id, "org-runner", RunnerCapabilities())
    registry.register(other_org_id, "other-runner", RunnerCapabilities())

    runners = registry.list_for_org(org_id)

    assert runners == [registration]


def test_deregister_removes_runner() -> None:
    registry = RunnerRegistry()
    registration, _ = registry.register(uuid4(), "private-runner", RunnerCapabilities())

    assert registry.deregister(registration.runner_id) is True
    assert registry.get(registration.runner_id) is None
    assert registry.deregister(registration.runner_id) is False
