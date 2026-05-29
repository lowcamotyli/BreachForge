from __future__ import annotations

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.reporting import ReportingService
from storage.db.session import get_db

router = APIRouter()


@router.get("/scans/{scan_id}/report")
async def get_report(
    scan_id: UUID,
    format: Literal["json", "markdown", "sarif", "html"] = Query(default="json"),
    db: AsyncSession = Depends(get_db),
) -> Response:
    reporting_service = ReportingService(db=db)

    try:
        payload = await reporting_service.export(scan_id=scan_id, fmt=format)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc

    media_type_map = {
        "json": "application/json",
        "markdown": "text/markdown",
        "sarif": "application/sarif+json",
        "html": "text/html",
    }
    media_type = media_type_map.get(format, "application/json")
    return Response(content=payload, media_type=media_type, status_code=status.HTTP_200_OK)
