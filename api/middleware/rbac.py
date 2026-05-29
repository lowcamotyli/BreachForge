from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies.auth import VerifiedActor, get_verified_actor
from storage.db.models import OrgMember as OrgMemberRow
from storage.db.models import OrgRole


_ROLE_RANK: dict[OrgRole, int] = {
    OrgRole.owner: 5,
    OrgRole.appsec_admin: 4,
    OrgRole.developer: 3,
    OrgRole.auditor: 2,
    OrgRole.runner: 1,
}


@dataclass
class RoleAssignment:
    org_id: UUID
    email: str
    role: OrgRole


class RoleStore:
    async def assign(self, db: AsyncSession, org_id: UUID, email: str, role: OrgRole) -> None:
        existing = await db.execute(
            select(OrgMemberRow).where(OrgMemberRow.org_id == org_id, OrgMemberRow.user_email == email.lower())
        )
        existing_row = existing.scalar_one_or_none()
        if existing_row:
            existing_row.role = role
        else:
            db.add(OrgMemberRow(org_id=org_id, user_email=email.lower(), role=role))
        await db.commit()

    async def get_role(self, db: AsyncSession, org_id: UUID, email: str) -> OrgRole | None:
        result = await db.execute(
            select(OrgMemberRow).where(OrgMemberRow.org_id == org_id, OrgMemberRow.user_email == email.lower())
        )
        row = result.scalar_one_or_none()
        return row.role if row else None

    async def has_role(self, db: AsyncSession, org_id: UUID, email: str, minimum_role: OrgRole) -> bool:
        current = await self.get_role(db, org_id, email)
        if current is None:
            return False
        return _ROLE_RANK[current] >= _ROLE_RANK[minimum_role]

    async def remove(self, db: AsyncSession, org_id: UUID, email: str) -> bool:
        result = await db.execute(
            delete(OrgMemberRow)
            .where(OrgMemberRow.org_id == org_id, OrgMemberRow.user_email == email.lower())
            .returning(OrgMemberRow.id)
        )
        await db.commit()
        return result.rowcount > 0

    async def list_members(self, db: AsyncSession, org_id: UUID) -> list[RoleAssignment]:
        result = await db.execute(select(OrgMemberRow).where(OrgMemberRow.org_id == org_id).order_by(OrgMemberRow.user_email))
        rows = sorted(result.scalars().all(), key=lambda row: row.user_email)
        return [RoleAssignment(org_id=org_id, email=row.user_email, role=row.role) for row in rows]


role_store = RoleStore()


def _extract_org_id(request: Request, org_id_header: str | None) -> UUID:
    path_org_id = request.path_params.get("org_id")
    candidate = path_org_id or org_id_header
    if candidate is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="missing org context")
    try:
        return UUID(str(candidate))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid org context") from exc


def require_role(minimum_role: OrgRole):
    async def _require(
        request: Request,
        actor: VerifiedActor = Depends(get_verified_actor),
        org_id_header: str | None = Header(default=None, alias="X-Org-ID"),
    ) -> None:
        org_id = _extract_org_id(request, org_id_header)
        if actor.org_id != org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="wrong org")
        if _ROLE_RANK[actor.role] < _ROLE_RANK[minimum_role]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")

    return Depends(_require)


__all__ = ["OrgRole", "RoleStore", "VerifiedActor", "role_store", "require_role"]
