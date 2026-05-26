from __future__ import annotations

from typing import Any, Literal

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


class ScanCreate(BaseModel):
    target_url: str = Field(min_length=1)
    allowed_domains: list[str] | None = None
    policy: ScanPolicy = Field(default_factory=ScanPolicy)
    unauth_mode: bool = False
    enable_business_logic_mutations: bool = False
    auth_context: AuthContextCreate | None = None
    identities: list[IdentityReference] | None = None
