from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


class AuthContextCreate(BaseModel):
    type: Literal["credential", "session", "token", "none"]
    credentials: dict[str, str] | None = None
    cookies: list[dict[str, Any]] | None = None
    bearer_token: str | None = None
    refresh_token: str | None = None
    totp_seed: str | None = None
    login_recipe: dict[str, Any] | None = None


class IdentityReference(BaseModel):
    name: str
    auth_context: AuthContextCreate
    role_hint: str | None = None
    tenant_hint: str | None = None
    auth_state: Literal["active", "pending", "expired"] = "active"


class ScanPolicy(BaseModel):
    allowed_domains: list[str] = Field(default_factory=list)
    max_requests: int = 500
    mutating_allowed: bool = False
    replay_allowed: bool = False
    oob_allowed: bool = False


class ScopePolicy(BaseModel):
    allowed_domains: list[str] = []
    denied_path_patterns: list[str] = []


class MethodClassPolicy(BaseModel):
    allow_read: bool = True
    allow_write_safe: bool = False
    allow_write_reversible: bool = False
    allow_destructive: bool = False
    allow_credential_sensitive: bool = False


class DestructiveBudget(BaseModel):
    max_destructive_probes: int = 0
    require_explicit_confirmation: bool = True


class TimeWindow(BaseModel):
    start_hour: int = 0
    end_hour: int = 23
    weekdays: list[int] = list(range(7))


class ScanPolicyV2(BaseModel):
    scope: ScopePolicy = Field(default_factory=ScopePolicy)
    method_classes: MethodClassPolicy = Field(default_factory=MethodClassPolicy)
    destructive_budget: DestructiveBudget = Field(default_factory=DestructiveBudget)
    time_windows: list[TimeWindow] = []
    version: str = "2"


class ScanCreate(BaseModel):
    target_url: str = Field(min_length=1)
    allowed_domains: list[str] | None = None
    policy: ScanPolicy = Field(default_factory=ScanPolicy)
    policy_v2: ScanPolicyV2 | None = None
    unauth_mode: bool = False
    enable_business_logic_mutations: bool = False
    auth_context: AuthContextCreate | None = None
    identities: list[IdentityReference] | None = None
    preferred_provider: str | None = None


class CreateSuppressionRequest(BaseModel):
    finding_id: UUID
    proof_hash: str
    suppression_type: Literal["false_positive", "accepted_risk", "wont_fix"]
    reason: str
    approved_by: str
    expires_at: datetime | None = None
