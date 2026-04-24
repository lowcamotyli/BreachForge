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


class ScanCreate(BaseModel):
    target_url: str = Field(min_length=1)
    allowed_domains: list[str] | None = None
    auth_context: AuthContextCreate
