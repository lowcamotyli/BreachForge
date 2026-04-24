from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.models.responses import FindingResponse
from storage.db.models import Finding, Scan
from storage.db.session import get_db

router = APIRouter()


@router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
async def list_findings(scan_id: UUID, db: AsyncSession = Depends(get_db)) -> list[FindingResponse]:
    scan_result = await db.execute(select(Scan.id).where(Scan.id == scan_id))
    if scan_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    finding_result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .options(selectinload(Finding.affected_endpoint))
        .order_by(Finding.id)
    )
    findings = finding_result.scalars().all()

    return [
        FindingResponse(
            id=str(finding.id),
            title=finding.title,
            severity=finding.severity.value,
            attack_class=finding.attack_class,
            affected_endpoint=finding.affected_endpoint.url_pattern,
        )
        for finding in findings
    ]
