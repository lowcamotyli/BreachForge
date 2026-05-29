from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
import os
import random
import re
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

import httpx
import structlog
from redis import Redis

from api.middleware.logging import redact_for_audit
from api.models.requests import ScanPolicy
from control_plane.auth_manager import AuthManager, IdentityRole, SessionSnapshot
from control_plane.rate_limiter import DomainRateLimiter
from execution_plane.planner.decision_log import FeedbackPayload, TaskOutcome
from execution_plane.planner.planner import rq_enqueue_replan
from execution_plane.policy.kill_switch import KillSwitch, KillSwitchLevel
from execution_plane.workers.behavior_profiles import BehaviorConfig, BehaviorProfile, get_profile_config
from storage.evidence.state_store import StateSnapshot, StateStore
from storage.db.models import AttackTask, AuditEvent, AuditEventType, RawProbe
from storage.db.session import AsyncSessionLocal

logger = structlog.get_logger(__name__)
_SENSITIVE_LOG_KEYS = {"authorization", "cookie", "x-auth-token", "password", "token", "x-api-key"}
_CHAIN_EXTRACT_KEY_PATTERN = re.compile(r"(^id$|_id$|id$|token|session)", re.IGNORECASE)
BUSINESS_LOGIC_MUTATING_CLASSES = frozenset(
    {
        "coupon_stacking",
        "negative_quantity",
        "price_tampering",
        "inventory_reservation_abuse",
        "approval_bypass",
        "double_spend",
        "cart_price_manipulation",
    }
)


class GuardrailViolation(RuntimeError):
    pass


class AuthExpiredError(RuntimeError):
    pass


class PolicyViolationError(RuntimeError):
    def __init__(self, reason: str, *, policy_field: str | None = None) -> None:
        super().__init__(reason)
        self.policy_field = policy_field


class KillSwitchError(RuntimeError):
    pass


class ProbeKilledException(Exception):
    pass


class AttackWorker:
    def __init__(
        self,
        redis_client: Redis | None = None,
        rate_limiter: DomainRateLimiter | None = None,
        auth_manager: AuthManager | None = None,
        behavior_profile: BehaviorProfile = BehaviorProfile.low_and_slow,
        kill_switch_redis: Redis | None = None,
    ) -> None:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._redis = redis_client or Redis.from_url(redis_url, decode_responses=True)
        self._kill_switch_redis: Redis | None = kill_switch_redis
        self._rate_limiter = rate_limiter or DomainRateLimiter(redis_client=self._redis)
        self._auth_manager = auth_manager
        self._behavior_config: BehaviorConfig = get_profile_config(behavior_profile)
        self._state_store = StateStore()
        self._snapshot_versions: dict[tuple[str, str], int] = {}
        self._rate_limit_wait_timeout_s = max(0.0, float(os.getenv("RATE_LIMIT_WAIT_TIMEOUT_S", "15")))
        self._scan_id: UUID | None = None
        self.scan_id: UUID | None = None
        self._kill_switch: KillSwitch | None = None

    async def execute(
        self,
        task: AttackTask,
        session: SessionSnapshot | None = None,
        identity_role: IdentityRole | str | None = None,
        identity_name: str | None = None,
        hypothesis_override: str | None = None,
        race_group_id: UUID | None = None,
        policy: ScanPolicy | None = None,
    ) -> RawProbe | None:
        self.scan_id = task.scan_id
        self._save_state_snapshot(task=task, status="pre")
        probe_race_group_id = race_group_id
        attack_class = str(task.attack_class).strip().lower()
        if (
            attack_class in BUSINESS_LOGIC_MUTATING_CLASSES
            and not self._is_business_logic_mutations_enabled(task)
        ):
            logger.warning(
                "business_logic_task_skipped",
                attack_class=task.attack_class,
                reason="business_logic_mutations_disabled",
            )
            return RawProbe(
                id=uuid4(),
                attack_task_id=task.id,
                worker_id=self._worker_id(),
                timestamp=datetime.now(UTC),
                request={
                    "method": "SKIPPED",
                    "url": str(task.endpoint.url_pattern) if task.endpoint is not None else "",
                    "headers": {},
                    "body": None,
                },
                response={
                    "status": "SKIPPED",
                    "headers": {},
                    "body": "business_logic_mutations_disabled",
                    "latency_ms": 0,
                },
            )
        endpoint = task.endpoint
        if endpoint is None:
            self._save_state_snapshot(task=task, status="failed")
            raise ValueError("AttackTask.endpoint must be loaded before execute()")

        if self._kill_switch_redis is not None:
            try:
                self._check_kill_switch(self._kill_switch_redis, str(task.scan_id))
            except KillSwitchError:
                await self._write_audit_event(
                    scan_id=task.scan_id,
                    event_type=AuditEventType.SCAN_KILLED,
                    actor="kill_switch",
                    details={"task_id": str(task.id)},
                    redact=True,
                )
                logger.warning("attack_task_killed", scan_id=str(task.scan_id), attack_task_id=str(task.id))
                return None

        if policy is not None:
            try:
                self._check_policy(task, policy)
            except PolicyViolationError as exc:
                policy_field = exc.policy_field or self._policy_field_from_reason(str(exc))
                await self._write_audit_event(
                    scan_id=task.scan_id,
                    event_type=AuditEventType.POLICY_VIOLATION,
                    actor="attack_worker",
                    details={"task_id": str(task.id), "reason": str(exc), "policy_field": policy_field},
                    redact=True,
                )
                logger.warning(
                    "attack_task_policy_blocked",
                    scan_id=str(task.scan_id),
                    attack_task_id=str(task.id),
                    reason=str(exc),
                )
                return None

        raw_probe: RawProbe | None = None
        result_confidence: float | None = None
        try:
            hypothesis_config = self._parse_hypothesis(hypothesis_override if hypothesis_override is not None else task.hypothesis)
            task_identity_role, task_identity_name = self._resolve_task_identity_request(
                task=task,
                hypothesis_config=hypothesis_config,
                explicit_identity_role=identity_role,
                explicit_identity_name=identity_name,
            )
            try:
                execution_session = await self._resolve_execution_session(
                    task=task,
                    provided_session=session,
                    identity_role=task_identity_role,
                    identity_name=task_identity_name,
                )
            except Exception:
                self._save_state_snapshot(task=task, status="failed")
                raise
            result_confidence = self._extract_result_confidence(hypothesis_config)
            chain_steps = hypothesis_config.get("chain_steps")
            if isinstance(chain_steps, list) and chain_steps:
                raw_probe = await self._execute_chain_steps(
                    task=task,
                    session=execution_session,
                    steps=chain_steps,
                    hypothesis_config=hypothesis_config,
                    current_identity=self._identity_label(task_identity_name if task_identity_name is not None else task_identity_role),
                    race_group_id=probe_race_group_id,
                )
            else:
                method = endpoint.method.upper()
                url = endpoint.url_pattern
                probe_type = hypothesis_config.get("probe_type")
                identity_selector = hypothesis_config.get("identity_selector")
                if probe_type in {"impact_secret_replay", "impact_secret_blast_radius"}:
                    self._enforce_safe_secret_replay_method(method=method, task_id=task.id)
                request_headers = self._build_probe_headers(
                    session=execution_session,
                    probe_type=probe_type,
                    identity_selector=identity_selector if isinstance(identity_selector, str) else None,
                )
                if probe_type in {"impact_secret_replay", "impact_secret_blast_radius"}:
                    self._apply_secret_replay_headers(headers=request_headers, hypothesis_config=hypothesis_config)
                request_body = self._build_request_body(task=task, probe_type=probe_type)
                worker_id = self._worker_id()

                domain = self._extract_request_domain(url)
                allowed_domains = self._resolve_allowed_domains(task)
                if not self._is_domain_allowed(domain, allowed_domains):
                    raise GuardrailViolation(
                        f"Out-of-scope target domain '{domain}' for task {task.id}; allowed domains: {sorted(allowed_domains)}"
                    )

                if (
                    self._rate_limiter.production_safe_mode
                    and not self._rate_limiter.allow_mutating_methods
                    and method in DomainRateLimiter.MUTATING_METHODS
                ):
                    raise GuardrailViolation(f"Mutating method '{method}' blocked in production-safe mode")

                await self._enforce_rate_limit(scan_id=str(task.scan_id), domain=domain, method=method, worker_id=worker_id)
                await self._apply_timing_profile(hypothesis_config.get("timing_profile"))

                cookies = self._build_probe_cookies(
                    session=execution_session,
                    probe_type=probe_type,
                    identity_selector=identity_selector if isinstance(identity_selector, str) else None,
                )
                async with httpx.AsyncClient(headers=request_headers, cookies=cookies, follow_redirects=True) as client:
                    request, response, latency_ms = await self._send_request(
                        client=client,
                        method=method,
                        url=url,
                        content=request_body,
                    )

                raw_probe = self._build_raw_probe(
                    task=task,
                    worker_id=worker_id,
                    request=request,
                    response=response,
                    latency_ms=latency_ms,
                    probe_type=probe_type,
                )
                if probe_race_group_id is not None:
                    raw_probe.request["_race_group_id"] = str(probe_race_group_id)

                evidence_metadata: dict[str, str] = {}
                if probe_type == "replay":
                    evidence_metadata["chain_id"] = f"{task.id}_replay"
                    logger.info(
                        "attack_probe_chain_entry",
                        attack_task_id=str(task.id),
                        entry=self._strip_sensitive({"chain_step": 1, "probe_type": "replay", "reused_token": True}),
                    )

                mutation_class = self._mutation_class_for_probe_type(probe_type)
                if mutation_class is not None:
                    evidence_metadata["mutation_class"] = mutation_class

                await self._publish_evidence(task.scan_id, raw_probe, metadata=evidence_metadata or None)
        except Exception:
            self._save_state_snapshot(task=task, status="failed")
            raise

        if probe_race_group_id is not None and raw_probe is not None:
            raw_probe.request["_race_group_id"] = str(probe_race_group_id)
        self._maybe_enqueue_adaptive_replan(task=task, raw_probe=raw_probe, confidence=result_confidence)

        status_value = raw_probe.response.get("status") if isinstance(raw_probe.response, dict) else None
        response_status_code = status_value if isinstance(status_value, int) else None
        body = raw_probe.response.get("body", "") if isinstance(raw_probe.response, dict) else ""
        ct = (
            str(raw_probe.response.get("headers", {}).get("content-type", ""))
            if isinstance(raw_probe.response, dict)
            else ""
        )
        self._save_state_snapshot(
            task=task,
            status="post",
            response_status_code=response_status_code,
            response_body=body[:4096] if isinstance(body, str) else str(body)[:4096],
            content_type=ct,
        )
        return raw_probe

    def _check_policy(self, task: AttackTask, policy: ScanPolicy) -> None:
        endpoint = task.endpoint
        method_hint = getattr(task, "http_method", None)
        raw_method = method_hint if isinstance(method_hint, str) and method_hint.strip() else (
            endpoint.method if endpoint is not None else ""
        )
        method = str(raw_method).upper()
        if method in {"POST", "PUT", "PATCH", "DELETE"} and not policy.mutating_allowed:
            raise PolicyViolationError("mutating request blocked by policy", policy_field="mutating_allowed")

        if policy.allowed_domains:
            target_url_hint = getattr(task, "target_url", None)
            target_url = (
                target_url_hint
                if isinstance(target_url_hint, str) and target_url_hint.strip()
                else (endpoint.url_pattern if endpoint is not None else "")
            )
            hostname = self._normalize_domain(urlparse(str(target_url)).hostname)
            allowed_domains = {self._normalize_domain(domain) for domain in policy.allowed_domains}
            if not hostname or hostname not in allowed_domains:
                raise PolicyViolationError("domain not in allowed_domains", policy_field="allowed_domains")

        if not policy.oob_allowed and self._task_has_oob_markers(task):
            raise PolicyViolationError("oob_callbacks_not_allowed", policy_field="oob_allowed")

        if not policy.replay_allowed and self._task_has_replay_markers(task):
            raise PolicyViolationError("replay_not_allowed", policy_field="replay_allowed")

        if self._scan_requests_sent(str(task.scan_id)) >= policy.max_requests:
            raise PolicyViolationError("max_requests_exceeded", policy_field="max_requests")

    def _check_kill_switch(self, redis: Redis, scan_id: str) -> None:
        scan_flag = redis.get(f"kill:{scan_id}")
        global_flag = redis.get("kill:global")
        if (isinstance(scan_flag, (str, bytes)) and scan_flag) or (
            isinstance(global_flag, (str, bytes)) and global_flag
        ):
            raise KillSwitchError(f"kill switch active for scan {scan_id}")

    def _task_has_oob_markers(self, task: AttackTask) -> bool:
        return self._task_contains_any_marker(task, ("oob", "callback", "burp_collaborator"))

    def _task_has_replay_markers(self, task: AttackTask) -> bool:
        return self._task_contains_any_marker(task, ("replay",))

    def _task_contains_any_marker(self, task: AttackTask, markers: tuple[str, ...]) -> bool:
        values: list[str] = []
        attack_class = getattr(task, "attack_class", None)
        if isinstance(attack_class, str) and attack_class.strip():
            values.append(attack_class)
        hypothesis = getattr(task, "hypothesis", None)
        if isinstance(hypothesis, str) and hypothesis.strip():
            values.append(hypothesis)
        target_parameter = getattr(task, "target_parameter", None)
        if isinstance(target_parameter, str) and target_parameter.strip():
            values.append(target_parameter)
        endpoint = getattr(task, "endpoint", None)
        url_pattern = getattr(endpoint, "url_pattern", None)
        if isinstance(url_pattern, str) and url_pattern.strip():
            values.append(url_pattern)
        haystack = " ".join(values).lower()
        return any(marker in haystack for marker in markers)

    def _scan_requests_sent(self, scan_id: str) -> int:
        try:
            value = self._redis.xlen(f"evidence:{scan_id}")
        except Exception:
            logger.exception("attack_worker_request_count_failed", scan_id=scan_id)
            return 0
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _policy_field_from_reason(self, reason: str) -> str:
        normalized = reason.strip().lower()
        if normalized == "mutating request blocked by policy":
            return "mutating_allowed"
        if normalized == "domain not in allowed_domains":
            return "allowed_domains"
        if normalized == "oob_callbacks_not_allowed":
            return "oob_allowed"
        if normalized == "replay_not_allowed":
            return "replay_allowed"
        if normalized == "max_requests_exceeded":
            return "max_requests"
        return "unknown"

    async def _write_audit_event(
        self,
        *,
        scan_id: UUID,
        event_type: AuditEventType,
        actor: str,
        details: dict[str, Any] | None,
        redact: bool,
    ) -> None:
        payload = redact_for_audit(details) if redact and isinstance(details, dict) else details
        try:
            async with AsyncSessionLocal() as db:
                db.add(
                    AuditEvent(
                        scan_id=scan_id,
                        event_type=event_type,
                        actor=actor,
                        details=payload,
                    )
                )
                await db.commit()
        except Exception:
            logger.exception(
                "attack_worker_audit_event_write_failed",
                scan_id=str(scan_id),
                event_type=str(event_type),
                actor=actor,
            )

    async def _execute_reconciliation_probe(
        self,
        task: AttackTask,
        session: SessionSnapshot | None,
    ) -> RawProbe | None:
        hypothesis = self._parse_hypothesis(task.hypothesis)
        endpoint = hypothesis.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.strip():
            return None
        parsed = urlparse(endpoint)
        if not parsed.scheme or not parsed.netloc:
            return None
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                request, response, latency_ms = await self._send_request(
                    client=client,
                    method="GET",
                    url=endpoint,
                )
            probe = self._build_raw_probe(
                task=task,
                worker_id=self._worker_id(),
                request=request,
                response=response,
                latency_ms=latency_ms,
                probe_type=None,
            )
            probe.request["_reconciliation"] = True
            race_group_hint = hypothesis.get("_race_group_id")
            if not isinstance(race_group_hint, str):
                race_group_hint = hypothesis.get("race_group_id")
            if isinstance(race_group_hint, str) and race_group_hint:
                probe.request["_race_group_id"] = race_group_hint
            return probe
        except Exception as exc:
            logger.warning("reconciliation_probe_failed", attack_task_id=str(task.id), error=str(exc))
            return None

    async def execute_race_group_with_reconciliation(
        self,
        tasks: list[AttackTask],
        session: SessionSnapshot | None,
        race_group_id: UUID,
    ) -> tuple[list[RawProbe], RawProbe | None]:
        if not tasks:
            return [], None
        race_probes = await asyncio.gather(*[self.execute(task, session, race_group_id=race_group_id) for task in tasks])
        reconciliation_probe = await self._execute_reconciliation_probe(tasks[0], session)
        return list(race_probes), reconciliation_probe

    async def _resolve_execution_session(
        self,
        task: AttackTask,
        provided_session: SessionSnapshot | None,
        identity_role: IdentityRole | str | None,
        identity_name: str | None,
    ) -> SessionSnapshot:
        unauth_mode = self._is_unauth_mode(task)
        selected_identity = identity_name if identity_name is not None else identity_role
        if unauth_mode or selected_identity == "anonymous":
            return self._empty_execution_session(task.scan_id)

        if self._auth_manager is None:
            if not unauth_mode and (identity_role is not None or identity_name is not None):
                raise GuardrailViolation("identity_role/identity_name requires AttackWorker(auth_manager=...)")
            if provided_session is None:
                raise GuardrailViolation("session is required when auth_manager is not configured")
            return provided_session

        self._scan_id = task.scan_id
        try:
            healthy = await self._auth_manager.health_check()
        except Exception as exc:
            await self._pause_for_auth_expired("auth_expired:auth_health_check_raised")
            raise AuthExpiredError(
                f"auth_expired: auth health check raised for scan_id={self._scan_id}: {type(exc).__name__}: {exc}"
            ) from exc

        if not healthy:
            raise AuthExpiredError(f"auth_expired: auth health check failed for scan_id={self._scan_id}")

        try:
            fresh_session = await self._auth_manager.get_session_snapshot(self._scan_id)
        except Exception as exc:
            await self._pause_for_auth_expired("auth_expired:get_session_snapshot_failed")
            raise AuthExpiredError(
                f"auth_expired: failed to fetch session snapshot for scan_id={self._scan_id}: {type(exc).__name__}: {exc}"
            ) from exc

        if selected_identity is None:
            return fresh_session

        try:
            identity_context = await self._auth_manager.get_identity_context(scan_id=self._scan_id, role=selected_identity)
        except RuntimeError as exc:
            if isinstance(selected_identity, str):
                raise AuthExpiredError(
                    f"identity_not_found: {selected_identity!r} not in identity matrix for scan {self._scan_id}"
                ) from exc
            await self._pause_for_auth_expired("auth_expired:get_identity_context_failed")
            raise AuthExpiredError(
                f"auth_expired: failed to load identity context={selected_identity!r} for scan_id={self._scan_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        except Exception as exc:
            await self._pause_for_auth_expired("auth_expired:get_identity_context_failed")
            raise AuthExpiredError(
                f"auth_expired: failed to load identity context={selected_identity!r} for scan_id={self._scan_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        return identity_context.to_session_snapshot()

    def _empty_execution_session(self, scan_id: UUID) -> SessionSnapshot:
        return SessionSnapshot(
            scan_id=scan_id,
            cookies=[],
            auth_headers={},
            csrf_tokens={},
            local_storage={},
            session_storage={},
            cookie_count=0,
            has_auth_token=False,
        )

    async def _pause_for_auth_expired(self, reason: str) -> None:
        if self._auth_manager is None:
            return
        pause_with_error = getattr(self._auth_manager, "_pause_with_error", None)
        if pause_with_error is None:
            return
        if not callable(pause_with_error):
            return
        try:
            await pause_with_error(reason)
        except Exception:
            logger.exception("attack_worker_pause_for_auth_failed", scan_id=str(self._scan_id), reason=reason)

    async def _enforce_rate_limit(self, scan_id: str, domain: str, method: str, worker_id: str) -> None:
        def _acquire() -> bool:
            return self._rate_limiter.acquire_for_worker(scan_id=scan_id, domain=domain, worker_id=worker_id, method=method)

        deadline = time.monotonic() + self._rate_limit_wait_timeout_s
        while True:
            allowed = await asyncio.to_thread(_acquire)
            if allowed:
                return
            if time.monotonic() >= deadline:
                raise GuardrailViolation(
                    f"Rate-limiter denied request for scan={scan_id}, domain={domain}, worker={worker_id}, method={method}"
                )
            await asyncio.sleep(0.25)

    def _resolve_allowed_domains(self, task: AttackTask) -> set[str]:
        scan = task.scan
        if scan is None or scan.target is None:
            raise GuardrailViolation("AttackTask.scan.target must be loaded to enforce allowed_domains")

        config = scan.target.config
        if not isinstance(config, dict):
            raise GuardrailViolation("Target config must be a dict containing allowed_domains")

        allowed_domains = config.get("allowed_domains")
        if not isinstance(allowed_domains, list):
            raise GuardrailViolation("Target config.allowed_domains must be a non-empty list")

        normalized = {
            self._normalize_domain(value)
            for value in allowed_domains
            if isinstance(value, str) and self._normalize_domain(value)
        }
        if not normalized:
            raise GuardrailViolation("Target config.allowed_domains must include at least one valid domain")
        return normalized

    def _extract_request_domain(self, url: str) -> str:
        parsed = urlparse(url)
        domain = self._normalize_domain(parsed.hostname)
        if not domain:
            raise GuardrailViolation(f"Task URL has no valid host: {url}")
        return domain

    def _is_domain_allowed(self, domain: str, allowed_domains: set[str]) -> bool:
        for allowed in allowed_domains:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True
        return False

    def _normalize_domain(self, domain: str | None) -> str:
        if not domain:
            return ""
        return domain.strip().lower().rstrip(".")

    def _is_unauth_mode(self, task: AttackTask) -> bool:
        scan = task.scan
        if scan is None:
            return False
        scan_unauth_mode = getattr(scan, "unauth_mode", None)
        if isinstance(scan_unauth_mode, bool):
            return scan_unauth_mode
        target = getattr(scan, "target", None)
        config = getattr(target, "config", None)
        if isinstance(config, dict):
            return bool(config.get("unauth_mode"))
        return False

    def _is_business_logic_mutations_enabled(self, task: AttackTask) -> bool:
        scan = task.scan
        if scan is None:
            return False
        target = getattr(scan, "target", None)
        config = getattr(target, "config", None)
        if not isinstance(config, dict):
            return False
        return bool(config.get("enable_business_logic_mutations"))

    async def execute_safe_token_replay(self, finding: dict, in_scope_domains: list[str]) -> dict:
        evidence = finding.get("evidence", {})
        token: str | None = None
        if isinstance(evidence, dict):
            for key in ("bearer_token", "api_key", "authorization", "token"):
                value = evidence.get(key)
                if isinstance(value, str) and value.strip():
                    token = value.strip()
                    break
        if token is None:
            raise ValueError("No replay token found in finding evidence")

        method = str(finding.get("method", "GET")).upper()
        if method != "GET":
            raise ValueError("Safe replay is GET-only")

        normalized_scope = {self._normalize_domain(domain) for domain in in_scope_domains if self._normalize_domain(domain)}
        if not normalized_scope:
            raise ValueError("Out-of-scope URL blocked by safe replay policy")

        endpoint = str(finding.get("endpoint", "") or "").strip()
        target_urls: list[str] = []
        if endpoint:
            parsed_endpoint = urlparse(endpoint)
            endpoint_host = self._normalize_domain(parsed_endpoint.hostname)
            if endpoint_host not in normalized_scope:
                raise ValueError("Out-of-scope URL blocked by safe replay policy")
            target_urls.append(endpoint)
            path_with_query = parsed_endpoint.path or "/"
            if parsed_endpoint.query:
                path_with_query = f"{path_with_query}?{parsed_endpoint.query}"
            for domain in normalized_scope:
                if len(target_urls) >= 3:
                    break
                if domain == endpoint_host:
                    continue
                scheme = parsed_endpoint.scheme or "https"
                target_urls.append(f"{scheme}://{domain}{path_with_query}")
        else:
            for domain in normalized_scope:
                if len(target_urls) >= 3:
                    break
                target_urls.append(f"https://{domain}/")

        target_urls = target_urls[:3]
        results: list[dict[str, Any]] = []
        headers = {"Authorization": f"Bearer {token}"}
        logger.info("safe_token_replay_started", token_used="[REDACTED]", requests_planned=len(target_urls))
        async with httpx.AsyncClient(follow_redirects=True) as client:
            for url in target_urls:
                parsed = urlparse(url)
                url_host = self._normalize_domain(parsed.hostname)
                if url_host not in normalized_scope:
                    raise ValueError("Out-of-scope URL blocked by safe replay policy")
                response = await client.get(url, headers=headers)
                results.append(
                    {
                        "url": url,
                        "status_code": response.status_code,
                        "response_size": len(response.content),
                        "content_type": response.headers.get("content-type", ""),
                    }
                )
        logger.info("safe_token_replay_completed", token_used="[REDACTED]", requests_made=len(results))
        return {
            "token_used": "[REDACTED]",
            "requests_made": len(results),
            "results": results,
            "scope_validated": True,
        }

    async def _publish_evidence(self, scan_id: Any, raw_probe: RawProbe, metadata: dict[str, str] | None = None) -> None:
        stream_key = f"evidence:{scan_id}"
        # Evidence stored unredacted per invariant #6; redaction at ReportingService only.
        state_evidence = self._state_dict_for_task(
            task_id=str(raw_probe.attack_task_id),
            scan_id=str(scan_id),
            step_id=str(raw_probe.attack_task_id),
        )
        payload = {
            "attack_task_id": str(raw_probe.attack_task_id),
            "worker_id": raw_probe.worker_id,
            "timestamp": raw_probe.timestamp.isoformat(),
            "request": json.dumps(raw_probe.request),
            "response": json.dumps(raw_probe.response),
        }
        if state_evidence is not None:
            payload["state_evidence"] = state_evidence
        if metadata:
            payload.update(metadata)

        await asyncio.to_thread(self._redis.xadd, stream_key, payload)
        logger.info(
            "attack_probe_published",
            scan_id=str(scan_id),
            attack_task_id=str(raw_probe.attack_task_id),
            stream_key=stream_key,
            metadata=self._strip_sensitive(metadata or {}),
            request=self._strip_sensitive(raw_probe.request),
            response=self._strip_sensitive(raw_probe.response),
        )

    def _strip_sensitive(self, value: dict[str, Any]) -> dict[str, Any]:
        stripped: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in _SENSITIVE_LOG_KEYS:
                continue
            if isinstance(item, dict):
                stripped[key] = self._strip_sensitive(item)
            else:
                stripped[key] = item
        return stripped

    def _build_request_headers(self, session: SessionSnapshot) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in session.auth_headers.items():
            headers[key] = value
        for key, value in session.csrf_tokens.items():
            headers[key] = value
        return headers

    def _build_probe_headers(
        self,
        session: SessionSnapshot,
        probe_type: Any,
        identity_selector: str | None = None,
    ) -> dict[str, str]:
        if isinstance(probe_type, str) and probe_type.startswith("ssrf_"):
            return {}

        if identity_selector == "anonymous":
            return {}

        if probe_type in {"impact_unauthenticated_repeat", "impact_secret_replay", "impact_secret_blast_radius"}:
            return {}

        if probe_type == "replay":
            replay_headers: dict[str, str] = {}
            for key, value in session.auth_headers.items():
                replay_headers[key] = value
            return replay_headers

        headers = self._build_request_headers(session)
        if probe_type == "token_swap":
            for key, value in list(headers.items()):
                if key.lower() in {"authorization", "x-auth-token"}:
                    headers[key] = f"{value}_swapped"
        elif probe_type == "stale_session":
            headers["X-Session-Age"] = "99999"
        return headers

    def _build_probe_cookies(
        self,
        session: SessionSnapshot,
        probe_type: Any,
        identity_selector: str | None = None,
    ) -> httpx.Cookies:
        if isinstance(probe_type, str) and probe_type.startswith("ssrf_"):
            return httpx.Cookies()
        if identity_selector == "anonymous":
            return httpx.Cookies()
        if probe_type in {"impact_unauthenticated_repeat", "impact_secret_replay", "impact_secret_blast_radius"}:
            return httpx.Cookies()
        return self._to_httpx_cookies(session.cookies)

    def _apply_secret_replay_headers(self, headers: dict[str, str], hypothesis_config: dict[str, Any]) -> None:
        if hypothesis_config.get("probe_type") not in {"impact_secret_replay", "impact_secret_blast_radius"}:
            return
        secret_value = hypothesis_config.get("secret_value")
        secret_kind = str(hypothesis_config.get("secret_kind") or "bearer").lower()
        if not isinstance(secret_value, str) or not secret_value.strip():
            raise GuardrailViolation("impact_secret_replay requires an in-memory secret_value")

        if secret_kind in {"api_key", "x_api_key"}:
            headers["X-API-Key"] = secret_value
            return
        headers["Authorization"] = secret_value if secret_value.lower().startswith("bearer ") else f"Bearer {secret_value}"

    def _enforce_safe_secret_replay_method(self, *, method: str, task_id: object) -> None:
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise GuardrailViolation(f"Safe secret replay only supports read-only methods for task {task_id}: {method}")

    def _build_request_body(self, task: AttackTask, probe_type: Any = None) -> bytes | None:
        if probe_type in {"impact_unauthenticated_repeat", "impact_secret_replay", "impact_secret_blast_radius"}:
            return None
        if not task.hypothesis:
            return None
        return task.hypothesis.encode("utf-8")

    def _build_chain_step_body(self, step: dict[str, Any], extracted_values: dict[str, Any]) -> bytes | None:
        for key in ("body", "json", "data"):
            if key not in step:
                continue
            rendered = self._apply_templates_to_value(step[key], extracted_values)
            if rendered is None:
                return None
            if isinstance(rendered, bytes):
                return rendered
            if isinstance(rendered, str):
                return rendered.encode("utf-8")
            return json.dumps(rendered, sort_keys=True).encode("utf-8")
        return None

    def _cap_blast_radius_body(self, body: bytes | str | None, *, max_bytes: int = 4096) -> str | None:
        if body is None:
            return None
        if isinstance(body, bytes):
            text = body.decode("utf-8", errors="replace")
        else:
            text = body
        return text[:max_bytes]

    def _parse_hypothesis(self, hypothesis: str | None) -> dict[str, Any]:
        if not hypothesis:
            return {}
        try:
            parsed = json.loads(hypothesis)
        except json.JSONDecodeError:
            return {}
        if not isinstance(parsed, dict):
            return {}
        return parsed

    def _resolve_task_identity_request(
        self,
        *,
        task: AttackTask,
        hypothesis_config: dict[str, Any],
        explicit_identity_role: IdentityRole | str | None,
        explicit_identity_name: str | None,
    ) -> tuple[IdentityRole | str | None, str | None]:
        if explicit_identity_role is not None or explicit_identity_name is not None:
            return explicit_identity_role, explicit_identity_name

        task_identity_name = getattr(task, "identity_name", None)
        if isinstance(task_identity_name, str) and task_identity_name.strip():
            return None, task_identity_name.strip()

        task_identity_role = getattr(task, "identity_role", None)
        if isinstance(task_identity_role, IdentityRole):
            return task_identity_role, None
        if isinstance(task_identity_role, str) and task_identity_role.strip():
            return task_identity_role.strip(), None

        hypothesis_identity_name = hypothesis_config.get("identity_name")
        if isinstance(hypothesis_identity_name, str) and hypothesis_identity_name.strip():
            return None, hypothesis_identity_name.strip()

        hypothesis_identity_role = hypothesis_config.get("identity_role")
        if isinstance(hypothesis_identity_role, str) and hypothesis_identity_role.strip():
            return hypothesis_identity_role.strip(), None

        identity_selector = hypothesis_config.get("identity_selector")
        if isinstance(identity_selector, str) and identity_selector.strip():
            selected = identity_selector.strip()
            if selected == "anonymous" or self._auth_manager is not None:
                return None, selected

        return None, None

    def _identity_request_from_step(self, step: dict[str, Any]) -> tuple[IdentityRole | str | None, str | None]:
        identity_name = step.get("identity_name")
        if isinstance(identity_name, str) and identity_name.strip():
            return None, identity_name.strip()

        identity_role = step.get("identity_role")
        if isinstance(identity_role, str) and identity_role.strip():
            return identity_role.strip(), None

        identity_selector = step.get("identity_selector")
        if isinstance(identity_selector, str) and identity_selector.strip():
            selected = identity_selector.strip()
            if selected == "anonymous" or self._auth_manager is not None:
                return None, selected

        return None, None

    def _identity_label(self, value: IdentityRole | str | None) -> str | None:
        if value is None:
            return None
        if isinstance(value, IdentityRole):
            return value.value
        text = str(value).strip()
        return text or None

    def _extract_result_confidence(self, hypothesis_config: dict[str, Any]) -> float | None:
        raw_confidence = hypothesis_config.get("confidence")
        if isinstance(raw_confidence, (int, float)):
            return float(raw_confidence)
        if isinstance(raw_confidence, str):
            try:
                return float(raw_confidence)
            except ValueError:
                return None
        return None

    def _maybe_enqueue_adaptive_replan(self, task: AttackTask, raw_probe: RawProbe, confidence: float | None) -> None:
        attack_class = str(task.attack_class).strip().lower()
        if attack_class not in {"sensitive_exposure", "secret_exposure"}:
            return
        if confidence is None or confidence < 0.5:
            return

        if os.getenv("ENABLE_ADAPTIVE_REPLAN", "1") == "0":
            logger.info(
                "adaptive_replan_skipped",
                scan_id=str(task.scan_id),
                attack_task_id=str(task.id),
                attack_class=task.attack_class,
                confidence=confidence,
            )
            return

        outcome = TaskOutcome.success if confidence >= 0.85 else TaskOutcome.needs_followup
        payload = FeedbackPayload(
            outcome=outcome,
            scan_id=str(task.scan_id),
            task_id=str(task.id),
            endpoint=str(task.endpoint.url_pattern) if task.endpoint is not None else "",
            finding_class=task.attack_class,
            confidence=confidence,
            follow_up_hints=["replay_with_token", "blast_radius_map"],
            parent_evidence_ref=str(raw_probe.id) if getattr(raw_probe, "id", None) is not None else str(task.id),
        )
        payload_dict = asdict(payload)
        payload_dict["outcome"] = outcome.value
        rq_enqueue_replan(scan_id=str(task.scan_id), feedback=payload_dict)
        logger.info(
            "adaptive_replan_enqueued",
            scan_id=str(task.scan_id),
            attack_task_id=str(task.id),
            attack_class=task.attack_class,
            confidence=confidence,
        )

    async def _apply_timing_profile(self, timing_profile: Any) -> None:
        if not isinstance(timing_profile, dict):
            return

        think_time_ms_raw = timing_profile.get("think_time_ms", 0)
        jitter_ms_raw = timing_profile.get("jitter_ms", 0)
        think_time_ms = min(max(self._coerce_int(think_time_ms_raw), 0), 2000)
        jitter_ms = min(max(self._coerce_int(jitter_ms_raw), 0), 500)

        if think_time_ms > 0:
            await asyncio.sleep(think_time_ms / 1000)
        if jitter_ms > 0:
            await asyncio.sleep(random.uniform(0.0, jitter_ms / 1000))

    def _coerce_int(self, value: Any) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return 0
        return 0

    def _mutation_class_for_probe_type(self, probe_type: Any) -> str | None:
        if probe_type == "token_swap":
            return "token_swap"
        if probe_type == "stale_session":
            return "stale_session"
        return None

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        cookies: httpx.Cookies | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[httpx.Request, httpx.Response, int]:
        # Check kill switch before each probe (kill switch takes priority over retry/replan)
        if hasattr(self, "_kill_switch") and self._kill_switch is not None:
            _ = KillSwitchLevel
            if self.scan_id is not None and self._kill_switch.is_active(str(self.scan_id)):
                raise ProbeKilledException(f"Scan {self.scan_id} killed via kill switch")
        if self._behavior_config.request_delay_ms > 0:
            await asyncio.sleep(self._behavior_config.request_delay_ms / 1000)
        if headers is None and params is None and cookies is None:
            request = client.build_request(method=method, url=url, content=content)
        else:
            try:
                request = client.build_request(
                    method=method,
                    url=url,
                    content=content,
                    headers=headers,
                    cookies=cookies,
                    params=params,
                )
            except TypeError:
                request = client.build_request(method=method, url=url, content=content)
                if headers:
                    request.headers.update(headers)
                if cookies:
                    request.headers.update(httpx.Headers({"cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())}))
                if params:
                    request.url = request.url.copy_merge_params(params)
        start = time.perf_counter()
        response = await client.send(request)
        latency_ms = int((time.perf_counter() - start) * 1000)
        return request, response, latency_ms

    def _build_raw_probe(
        self,
        task: AttackTask,
        worker_id: str,
        request: httpx.Request,
        response: httpx.Response,
        latency_ms: int,
        probe_type: Any = None,
    ) -> RawProbe:
        response_body: str | None = response.text
        if probe_type == "impact_secret_blast_radius":
            response_body = self._cap_blast_radius_body(response_body)
        return RawProbe(
            id=uuid4(),
            attack_task_id=task.id,
            worker_id=worker_id,
            timestamp=datetime.now(UTC),
            request={
                "method": request.method,
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": self._decode_request_body(request.content),
            },
            response={
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": response_body,
                "latency_ms": latency_ms,
            },
        )

    def _response_payload(self, response: httpx.Response, latency_ms: int) -> dict[str, Any]:
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": self._cap_blast_radius_body(response.text),
            "latency_ms": latency_ms,
        }

    async def _execute_chain_steps(
        self,
        task: AttackTask,
        session: SessionSnapshot,
        steps: list[Any],
        hypothesis_config: dict[str, Any],
        current_identity: str | None = None,
        race_group_id: UUID | None = None,
    ) -> RawProbe:
        endpoint = task.endpoint
        if endpoint is None:
            raise ValueError("AttackTask.endpoint must be loaded before execute()")

        worker_id = self._worker_id()
        allowed_domains = self._resolve_allowed_domains(task)
        extracted_values: dict[str, Any] = {}
        chain_entries: list[dict[str, Any]] = []
        read_probe_responses: list[dict[str, Any]] = []
        active_session = session
        active_identity = current_identity

        last_request: httpx.Request | None = None
        last_response: httpx.Response | None = None
        last_latency_ms = 0
        last_probe_type: Any = None

        async with httpx.AsyncClient(follow_redirects=True) as client:
            for idx, step in enumerate(steps, start=1):
                if not isinstance(step, dict):
                    continue

                step_identity_role, step_identity_name = self._identity_request_from_step(step)
                requested_identity = self._identity_label(
                    step_identity_name if step_identity_name is not None else step_identity_role
                )
                if requested_identity is not None and requested_identity != active_identity:
                    active_session = await self._resolve_execution_session(
                        task=task,
                        provided_session=active_session,
                        identity_role=step_identity_role,
                        identity_name=step_identity_name,
                    )
                    active_identity = requested_identity

                method = str(step.get("method") or endpoint.method).upper()
                step_url = str(step.get("url_pattern") or endpoint.url_pattern)
                url = self._apply_value_templates(step_url, extracted_values)
                probe_type = step.get("probe_type")
                identity_selector = step.get("identity_selector")
                last_probe_type = probe_type

                domain = self._extract_request_domain(url)
                if not self._is_domain_allowed(domain, allowed_domains):
                    raise GuardrailViolation(
                        f"Out-of-scope target domain '{domain}' for task {task.id}; allowed domains: {sorted(allowed_domains)}"
                    )
                if (
                    self._rate_limiter.production_safe_mode
                    and not self._rate_limiter.allow_mutating_methods
                    and method in DomainRateLimiter.MUTATING_METHODS
                ):
                    raise GuardrailViolation(f"Mutating method '{method}' blocked in production-safe mode")

                await self._enforce_rate_limit(scan_id=str(task.scan_id), domain=domain, method=method, worker_id=worker_id)
                await self._apply_timing_profile(hypothesis_config.get("timing_profile"))

                headers = self._build_probe_headers(
                    session=active_session,
                    probe_type=probe_type,
                    identity_selector=identity_selector if isinstance(identity_selector, str) else None,
                )
                cookies = self._build_probe_cookies(
                    session=active_session,
                    probe_type=probe_type,
                    identity_selector=identity_selector if isinstance(identity_selector, str) else None,
                )
                extra_headers = step.get("headers")
                if isinstance(extra_headers, dict):
                    for key, value in extra_headers.items():
                        if isinstance(key, str):
                            headers[key] = self._apply_value_templates(str(value), extracted_values)
                for key, value in extracted_values.items():
                    if self._is_sensitive_chain_key(key):
                        continue
                    header_name = f"X-Chain-{key}"
                    headers.setdefault(header_name, str(value))

                params_payload: dict[str, Any] = {}
                step_params = step.get("params")
                if isinstance(step_params, dict):
                    for key, value in step_params.items():
                        if isinstance(key, str):
                            params_payload[key] = self._apply_value_templates(str(value), extracted_values)
                for key, value in extracted_values.items():
                    if self._is_sensitive_chain_key(key):
                        continue
                    params_payload.setdefault(key, str(value))

                request_body = self._build_chain_step_body(step, extracted_values)
                request, response, latency_ms = await self._send_request(
                    client=client,
                    method=method,
                    url=url,
                    content=request_body,
                    headers=headers,
                    cookies=cookies,
                    params=params_payload or None,
                )
                last_request = request
                last_response = response
                last_latency_ms = latency_ms

                chain_entry = {"chain_step": idx, "probe_type": probe_type}
                if active_identity is not None:
                    chain_entry["identity_role"] = active_identity
                if probe_type == "replay":
                    chain_entry["reused_token"] = True
                mutation_class = self._mutation_class_for_probe_type(probe_type)
                if mutation_class is not None:
                    chain_entry["mutation_class"] = mutation_class

                extract_spec = step.get("extract")
                if isinstance(extract_spec, dict):
                    response_json = self._response_json(response)
                    for key, path in extract_spec.items():
                        if not isinstance(key, str) or not isinstance(path, str):
                            continue
                        extracted = self._extract_json_path(response_json, path)
                        if extracted is not None:
                            extracted_values[key] = extracted
                extracted_values.update(self._extract_patterned_json_values(self._response_json(response)))
                if extracted_values:
                    chain_entry["extracted_keys"] = sorted(extracted_values.keys())

                if method in DomainRateLimiter.MUTATING_METHODS:
                    await self._enforce_rate_limit(scan_id=str(task.scan_id), domain=domain, method="GET", worker_id=worker_id)
                    read_request, read_response, read_latency_ms = await self._send_request(
                        client=client,
                        method="GET",
                        url=url,
                        headers=headers,
                        cookies=cookies,
                        params=params_payload or None,
                    )
                    read_probe_response = self._response_payload(read_response, read_latency_ms)
                    read_probe_responses.append(
                        {
                            "chain_step": idx,
                            "request": {
                                "method": read_request.method,
                                "url": str(read_request.url),
                            },
                            "response": read_probe_response,
                        }
                    )
                    chain_entry["read_probe_response"] = read_probe_response

                chain_entries.append(chain_entry)
                logger.info(
                    "attack_probe_chain_entry",
                    attack_task_id=str(task.id),
                    entry=self._strip_sensitive(chain_entry),
                )

        if last_request is None or last_response is None:
            raise GuardrailViolation(f"No executable chain step found for task {task.id}")

        raw_probe = self._build_raw_probe(
            task=task,
            worker_id=worker_id,
            request=last_request,
            response=last_response,
            latency_ms=last_latency_ms,
            probe_type=last_probe_type,
        )
        if extracted_values:
            raw_probe.response["extracted_values"] = {
                key: "[REDACTED]" if self._is_sensitive_chain_key(key) else value
                for key, value in extracted_values.items()
            }
        if read_probe_responses:
            raw_probe.response["read_probe_responses"] = read_probe_responses
        if race_group_id is not None:
            raw_probe.request["_race_group_id"] = str(race_group_id)
        chain_metadata: dict[str, str] = {
            "chain_id": f"{task.id}_chain",
            "chain_entries": json.dumps(chain_entries),
        }
        chain_state_evidence = self._state_dict_for_task(
            task_id=str(task.id),
            scan_id=str(task.scan_id),
            step_id=str(raw_probe.attack_task_id),
        )
        if chain_state_evidence is not None:
            chain_metadata["state_evidence"] = chain_state_evidence
        await self._publish_evidence(
            task.scan_id,
            raw_probe,
            metadata=chain_metadata,
        )
        return raw_probe

    def _response_json(self, response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            return {}

    def _extract_json_path(self, payload: Any, path: str) -> Any:
        current: Any = payload
        for part in path.split("."):
            if isinstance(current, dict):
                if part not in current:
                    return None
                current = current[part]
                continue
            if isinstance(current, list):
                try:
                    index = int(part)
                except ValueError:
                    return None
                if index < 0 or index >= len(current):
                    return None
                current = current[index]
                continue
            return None
        return current

    def _extract_patterned_json_values(self, payload: Any) -> dict[str, Any]:
        extracted: dict[str, Any] = {}

        def _walk(value: Any) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if isinstance(key, str) and _CHAIN_EXTRACT_KEY_PATTERN.search(key) and self._is_scalar_chain_value(item):
                        extracted.setdefault(key, item)
                    _walk(item)
                return
            if isinstance(value, list):
                for item in value:
                    _walk(item)

        _walk(payload)
        return extracted

    def _is_scalar_chain_value(self, value: Any) -> bool:
        return isinstance(value, (str, int, float, bool)) and value not in ("", None)

    def _apply_value_templates(self, value: str, carried_values: dict[str, Any]) -> str:
        resolved = value
        for key, item in carried_values.items():
            resolved = resolved.replace("{" + key + "}", str(item))
            resolved = resolved.replace("{extracted." + key + "}", str(item))
        return resolved

    def _apply_templates_to_value(self, value: Any, extracted_values: dict[str, Any]) -> Any:
        if isinstance(value, str):
            return self._apply_value_templates(value, extracted_values)
        if isinstance(value, list):
            return [self._apply_templates_to_value(item, extracted_values) for item in value]
        if isinstance(value, dict):
            return {
                str(key): self._apply_templates_to_value(item, extracted_values)
                for key, item in value.items()
            }
        return value

    def _is_sensitive_chain_key(self, key: str) -> bool:
        lowered = key.lower()
        return lowered in _SENSITIVE_LOG_KEYS or any(token in lowered for token in ("token", "session", "secret", "password"))

    def _to_httpx_cookies(self, cookies: list[dict[str, Any]]) -> httpx.Cookies:
        jar = httpx.Cookies()
        for cookie in cookies:
            name = cookie.get("name")
            value = cookie.get("value")
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            jar.set(
                name,
                value,
                domain=cookie.get("domain"),
                path=cookie.get("path", "/"),
            )
        return jar

    def _decode_request_body(self, body: bytes | None) -> str:
        if not body:
            return ""
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return body.decode("utf-8", errors="replace")

    def _worker_id(self) -> str:
        hostname = os.getenv("HOSTNAME", "worker")
        pid = os.getpid()
        return f"{hostname}:{pid}"

    def _save_state_snapshot(
        self,
        task: AttackTask,
        status: str,
        response_status_code: int | None = None,
        response_body: str | None = None,
        content_type: str | None = None,
    ) -> None:
        scan_id = str(task.scan_id)
        step_id = str(task.id)
        version_key = (scan_id, step_id)
        next_version = self._snapshot_versions.get(version_key, 0) + 1
        self._snapshot_versions[version_key] = next_version
        body_json_keys: list[str] = []
        if response_body:
            try:
                parsed_body = json.loads(response_body[:4096])
                if isinstance(parsed_body, dict):
                    body_json_keys = sorted(key for key in parsed_body.keys() if isinstance(key, str))
            except (json.JSONDecodeError, TypeError):
                body_json_keys = []

        state_dict: dict[str, Any] = {
            "task_id": str(task.id),
            "status": status,
            "response_status_code": response_status_code,
            "body_size": len(response_body) if response_body else 0,
            "content_type": content_type or "",
            "body_json_keys": body_json_keys,
        }

        self._state_store.save_snapshot(
            StateSnapshot(
                scan_id=scan_id,
                step_id=step_id,
                timestamp=datetime.now(UTC),
                state_dict=state_dict,
                version=next_version,
            )
        )

    def _state_dict_for_task(self, task_id: str, scan_id: str, step_id: str) -> str | None:
        _ = task_id
        before_after = self._state_store.get_before_after(scan_id, step_id)
        if before_after is None:
            return None
        before_snap, after_snap = before_after
        if before_snap is None or after_snap is None:
            return None
        return json.dumps({"before": before_snap.state_dict, "after": after_snap.state_dict})
