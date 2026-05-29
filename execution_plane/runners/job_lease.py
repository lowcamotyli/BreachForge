from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from uuid import UUID, uuid4


class JobStatus(str, Enum):
    pending = "pending"
    leased = "leased"
    running = "running"
    completed = "completed"
    failed = "failed"
    expired = "expired"


@dataclass
class JobPackage:
    job_id: UUID
    scan_id: UUID
    org_id: UUID
    runner_id: UUID | None
    attack_class: str
    endpoint_url: str
    method: str
    hypothesis: str
    auth_token_hash: str
    payload_spec: dict[str, object]
    created_at: datetime
    expires_at: datetime
    signature: str


@dataclass
class JobLease:
    lease_id: UUID
    job_id: UUID
    runner_id: UUID
    leased_at: datetime
    expires_at: datetime
    heartbeat_at: datetime


class JobLeaseManager:
    def __init__(self) -> None:
        self.pending_queue: list[UUID] = []
        self.jobs: dict[UUID, JobPackage] = {}
        self.job_status: dict[UUID, JobStatus] = {}
        self.leases: dict[UUID, JobLease] = {}

    def enqueue(
        self,
        scan_id: UUID,
        org_id: UUID,
        attack_class: str,
        endpoint_url: str,
        method: str,
        hypothesis: str,
        payload_spec: dict[str, object],
        auth_token_hash: str,
    ) -> JobPackage:
        now = datetime.now(UTC)
        job = JobPackage(
            job_id=uuid4(),
            scan_id=scan_id,
            org_id=org_id,
            runner_id=None,
            attack_class=attack_class,
            endpoint_url=endpoint_url,
            method=method,
            hypothesis=hypothesis,
            auth_token_hash=auth_token_hash,
            payload_spec=dict(payload_spec),
            created_at=now,
            expires_at=now + timedelta(minutes=10),
            signature="",
        )
        self.jobs[job.job_id] = job
        self.job_status[job.job_id] = JobStatus.pending
        self.pending_queue.append(job.job_id)
        return job

    def pull(self, runner_id: UUID, org_id: UUID) -> JobPackage | None:
        for index, job_id in enumerate(self.pending_queue):
            job = self.jobs[job_id]
            if job.org_id != org_id:
                continue

            self.pending_queue.pop(index)
            now = datetime.now(UTC)
            lease = JobLease(
                lease_id=uuid4(),
                job_id=job.job_id,
                runner_id=runner_id,
                leased_at=now,
                expires_at=now + timedelta(minutes=5),
                heartbeat_at=now,
            )
            self.leases[lease.lease_id] = lease
            candidate = replace(job, runner_id=runner_id, signature="")
            signed = replace(candidate, signature=self._sign_payload(candidate, job.auth_token_hash))
            self.jobs[job.job_id] = signed
            self.job_status[job.job_id] = JobStatus.leased
            return signed
        return None

    def heartbeat_lease(self, lease_id: UUID, runner_id: UUID) -> bool:
        lease = self.leases.get(lease_id)
        if lease is None or lease.runner_id != runner_id:
            return False
        if self.job_status.get(lease.job_id) not in {JobStatus.leased, JobStatus.running}:
            return False

        now = datetime.now(UTC)
        lease.heartbeat_at = now
        self.job_status[lease.job_id] = JobStatus.running
        return True

    def complete(self, lease_id: UUID, runner_id: UUID, success: bool) -> bool:
        lease = self.leases.get(lease_id)
        if lease is None or lease.runner_id != runner_id:
            return False

        self.job_status[lease.job_id] = JobStatus.completed if success else JobStatus.failed
        return True

    def expire_stale_leases(self, max_age_seconds: int = 300) -> int:
        now = datetime.now(UTC)
        expired_count = 0
        for lease in list(self.leases.values()):
            age = (now - lease.heartbeat_at).total_seconds()
            if age <= max_age_seconds:
                continue
            if self.job_status.get(lease.job_id) in {JobStatus.completed, JobStatus.failed}:
                continue

            self.job_status[lease.job_id] = JobStatus.expired
            if lease.job_id not in self.pending_queue:
                self.pending_queue.append(lease.job_id)
            self.job_status[lease.job_id] = JobStatus.pending
            del self.leases[lease.lease_id]
            expired_count += 1
        return expired_count

    def verify_signature(self, package: JobPackage, runner_token_hash: str) -> bool:
        expected = self._sign_payload(package, runner_token_hash)
        return hmac.compare_digest(package.signature, expected)

    def _sign_payload(self, package: JobPackage, runner_token_hash: str) -> str:
        body = {
            "job_id": str(package.job_id),
            "scan_id": str(package.scan_id),
            "org_id": str(package.org_id),
            "runner_id": str(package.runner_id) if package.runner_id is not None else "",
            "attack_class": package.attack_class,
            "endpoint_url": package.endpoint_url,
            "method": package.method,
            "hypothesis": package.hypothesis,
            "auth_token_hash": package.auth_token_hash,
            "payload_spec": package.payload_spec,
            "created_at": package.created_at.isoformat(),
            "expires_at": package.expires_at.isoformat(),
        }
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        key = runner_token_hash.encode("utf-8")
        return hmac.new(key, encoded, hashlib.sha256).hexdigest()
