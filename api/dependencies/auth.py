from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import structlog
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from storage.db.models import APIKey
from storage.db.models import OrgMember as OrgMemberRow
from storage.db.models import OrgRole
from storage.db.session import get_db

logger = structlog.get_logger(__name__)
_DEV_MODE_ENABLED = os.getenv("PROOFSCAN_DEV_MODE") == "1"

if _DEV_MODE_ENABLED:
    logger.warning("Dev mode active: X-Actor-Email bypass enabled — DO NOT USE IN PRODUCTION")


@dataclass
class VerifiedActor:
    org_id: UUID
    email: str
    role: OrgRole


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    value = token.strip()
    return value or None


async def _lookup_role(db: AsyncSession, org_id: UUID, user_email: str) -> OrgRole:
    member_result = await db.execute(
        select(OrgMemberRow.role).where(OrgMemberRow.org_id == org_id, OrgMemberRow.user_email == user_email)
    )
    member_role = member_result.scalar_one_or_none()
    if member_role is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="actor not found in org")
    return member_role


async def get_verified_actor(
    authorization: str | None = Header(default=None, alias="Authorization"),
    actor_email_header: str | None = Header(default=None, alias="X-Actor-Email"),
    org_id_header: str | None = Header(default=None, alias="X-Org-ID"),
    db: AsyncSession = Depends(get_db),
) -> VerifiedActor:
    bearer_token = _extract_bearer_token(authorization)

    if bearer_token is None and _DEV_MODE_ENABLED and authorization is None and actor_email_header and org_id_header:
        try:
            org_id = UUID(org_id_header)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="actor not found in org") from exc
        role = await _lookup_role(db, org_id, actor_email_header)
        return VerifiedActor(org_id=org_id, email=actor_email_header, role=role)

    if bearer_token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired API key")

    key_hash = hashlib.sha256(bearer_token.encode()).hexdigest()
    now_utc = datetime.now(UTC)

    key_result = await db.execute(
        select(APIKey).where(
            APIKey.key_hash == key_hash,
            APIKey.revoked_at.is_(None),
            (APIKey.expires_at.is_(None) | (APIKey.expires_at > now_utc)),
        )
    )
    key = key_result.scalar_one_or_none()
    if key is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired API key")

    role = await _lookup_role(db, key.org_id, key.created_by)

    key.last_used_at = now_utc
    await db.commit()

    return VerifiedActor(org_id=key.org_id, email=key.created_by, role=role)
