from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.middleware.rbac import OrgRole, require_role
from storage.db.models import OrgMember, Organization
from storage.db.session import get_db

router = APIRouter()


class OrgCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=128)


class OrgResponse(BaseModel):
    org_id: UUID
    name: str
    slug: str
    created_at: datetime


class MemberRequest(BaseModel):
    email: str
    role: OrgRole


class MemberResponse(BaseModel):
    email: str
    role: OrgRole


@router.post("/orgs", response_model=OrgResponse, status_code=status.HTTP_201_CREATED)
async def create_org(payload: OrgCreateRequest, db: AsyncSession = Depends(get_db)) -> OrgResponse:
    row = Organization(name=payload.name, slug=payload.slug)
    try:
        db.add(row)
        await db.commit()
        await db.refresh(row)
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="db error") from exc
    return OrgResponse(org_id=row.id, name=row.name, slug=row.slug, created_at=row.created_at)


@router.get("/orgs/{org_id}", response_model=OrgResponse)
async def get_org(org_id: UUID, db: AsyncSession = Depends(get_db)) -> OrgResponse:
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="org not found")
    return OrgResponse(org_id=row.id, name=row.name, slug=row.slug, created_at=row.created_at)


@router.post("/orgs/{org_id}/members", response_model=MemberResponse, dependencies=[require_role(OrgRole.appsec_admin)])
async def add_member(org_id: UUID, payload: MemberRequest, db: AsyncSession = Depends(get_db)) -> MemberResponse:
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    if org_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="org not found")
    try:
        db.add(OrgMember(org_id=org_id, user_email=payload.email.lower(), role=payload.role))
        await db.commit()
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="db error") from exc
    return MemberResponse(email=payload.email.lower(), role=payload.role)


@router.get("/orgs/{org_id}/members", response_model=list[MemberResponse], dependencies=[require_role(OrgRole.auditor)])
async def list_members(org_id: UUID, db: AsyncSession = Depends(get_db)) -> list[MemberResponse]:
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    if org_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="org not found")
    result = await db.execute(
        select(OrgMember).where(OrgMember.org_id == org_id).order_by(OrgMember.user_email)
    )
    return [MemberResponse(email=m.user_email, role=m.role) for m in result.scalars().all()]


@router.delete(
    "/orgs/{org_id}/members/{email}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[require_role(OrgRole.appsec_admin)],
)
async def remove_member(org_id: UUID, email: str, db: AsyncSession = Depends(get_db)) -> None:
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    if org_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="org not found")
    try:
        result = await db.execute(
            delete(OrgMember).where(OrgMember.org_id == org_id, OrgMember.user_email == email.lower())
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="db error") from exc
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="member not found")


__all__ = ["router"]
