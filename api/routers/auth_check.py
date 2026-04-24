from __future__ import annotations

from fastapi import APIRouter

from api.models.requests import AuthContextCreate

router = APIRouter()


def _has_non_empty_text(value: str | None) -> bool:
    return bool(value and value.strip())


def _has_non_empty_credentials(credentials: dict[str, str] | None) -> bool:
    if not credentials:
        return False
    return any(_has_non_empty_text(v) for v in credentials.values())


@router.post("/verify")
async def verify_auth_context(payload: AuthContextCreate) -> dict[str, bool | str]:
    if payload.type == "none":
        return {"valid": True, "reason": "No auth required"}

    if payload.type == "credential":
        if _has_non_empty_credentials(payload.credentials):
            return {"valid": True, "reason": "Credential auth material is present"}
        return {"valid": False, "reason": "credentials must contain at least one non-empty value"}

    if payload.type == "session":
        has_cookies = bool(payload.cookies)
        has_login_recipe = bool(payload.login_recipe)
        if has_cookies or has_login_recipe:
            return {"valid": True, "reason": "Session auth material is present"}
        return {"valid": False, "reason": "cookies or login_recipe must be provided"}

    if payload.type == "token":
        if _has_non_empty_text(payload.bearer_token) or _has_non_empty_text(payload.refresh_token):
            return {"valid": True, "reason": "Token auth material is present"}
        return {"valid": False, "reason": "bearer_token or refresh_token must be provided"}

    return {"valid": False, "reason": "Unsupported auth context type"}
