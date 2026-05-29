from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from execution_plane.runners.job_lease import JobLeaseManager, JobStatus


def test_enqueue_creates_pending_job() -> None:
    manager = JobLeaseManager()

    job = manager.enqueue(
        scan_id=uuid4(),
        org_id=uuid4(),
        attack_class="bola",
        endpoint_url="https://api.example.com/users",
        method="GET",
        hypothesis="Tenant isolation bypass",
        payload_spec={"probe": "idor"},
        auth_token_hash="hashed-token",
    )

    assert manager.job_status[job.job_id] == JobStatus.pending
    assert job.auth_token_hash == "hashed-token"


def test_pull_returns_job_for_correct_org_and_creates_lease() -> None:
    manager = JobLeaseManager()
    org_id = uuid4()
    runner_id = uuid4()
    job = manager.enqueue(uuid4(), org_id, "bola", "https://api.example.com", "GET", "h", {"a": 1}, "token-hash")

    pulled = manager.pull(runner_id=runner_id, org_id=org_id)

    assert pulled is not None
    assert pulled.job_id == job.job_id
    assert pulled.runner_id == runner_id
    assert manager.job_status[job.job_id] == JobStatus.leased
    assert len(manager.leases) == 1


def test_pull_returns_none_for_runner_in_different_org() -> None:
    manager = JobLeaseManager()
    job = manager.enqueue(uuid4(), uuid4(), "bola", "https://api.example.com", "GET", "h", {"a": 1}, "token-hash")

    pulled = manager.pull(runner_id=uuid4(), org_id=uuid4())

    assert pulled is None
    assert manager.job_status[job.job_id] == JobStatus.pending


def test_pull_model_runner_pulls_not_enqueue() -> None:
    manager = JobLeaseManager()
    org_id = uuid4()

    queued = manager.enqueue(uuid4(), org_id, "bola", "https://api.example.com", "GET", "h", {"a": 1}, "token-hash")

    assert manager.job_status[queued.job_id] == JobStatus.pending
    assert len(manager.leases) == 0

    pulled = manager.pull(runner_id=uuid4(), org_id=org_id)

    assert pulled is not None
    assert len(manager.leases) == 1


def test_heartbeat_lease_updates_timestamp() -> None:
    manager = JobLeaseManager()
    org_id = uuid4()
    runner_id = uuid4()
    manager.enqueue(uuid4(), org_id, "bola", "https://api.example.com", "GET", "h", {"a": 1}, "token-hash")
    manager.pull(runner_id=runner_id, org_id=org_id)
    lease = next(iter(manager.leases.values()))
    original = lease.heartbeat_at

    ok = manager.heartbeat_lease(lease.lease_id, runner_id)

    assert ok is True
    assert lease.heartbeat_at >= original


def test_complete_marks_lease_done() -> None:
    manager = JobLeaseManager()
    org_id = uuid4()
    runner_id = uuid4()
    job = manager.enqueue(uuid4(), org_id, "bola", "https://api.example.com", "GET", "h", {"a": 1}, "token-hash")
    manager.pull(runner_id=runner_id, org_id=org_id)
    lease = next(iter(manager.leases.values()))

    ok = manager.complete(lease.lease_id, runner_id, success=True)

    assert ok is True
    assert manager.job_status[job.job_id] == JobStatus.completed


def test_verify_signature_succeeds_with_correct_hash_fails_with_wrong_hash() -> None:
    manager = JobLeaseManager()
    org_id = uuid4()
    runner_id = uuid4()
    manager.enqueue(uuid4(), org_id, "bola", "https://api.example.com", "GET", "h", {"a": 1}, "token-hash")

    package = manager.pull(runner_id=runner_id, org_id=org_id)

    assert package is not None
    assert manager.verify_signature(package, "token-hash") is True
    assert manager.verify_signature(package, "wrong-hash") is False


def test_expire_stale_leases_requeues_expired_leases() -> None:
    manager = JobLeaseManager()
    org_id = uuid4()
    runner_id = uuid4()
    job = manager.enqueue(uuid4(), org_id, "bola", "https://api.example.com", "GET", "h", {"a": 1}, "token-hash")
    manager.pull(runner_id=runner_id, org_id=org_id)
    lease = next(iter(manager.leases.values()))
    lease.heartbeat_at = datetime.now(UTC) - timedelta(seconds=301)

    expired = manager.expire_stale_leases(max_age_seconds=300)

    assert expired == 1
    assert job.job_id in manager.pending_queue
    assert manager.job_status[job.job_id] == JobStatus.pending
