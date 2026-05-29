from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.requests import ScanCreate
from api.routers.scans import create_scan
from storage.db.session import get_db

logger = structlog.get_logger()
router = APIRouter(prefix="/webhooks", tags=["ci-webhook"])


class WebhookTriggerRequest(BaseModel):
    target_url: str
    gate_config: dict[str, Any] | None = None
    source: str = "generic"
    signature: str | None = None


class WebhookTriggerResponse(BaseModel):
    scan_id: str
    status_url: str
    source: str


def _validate_signature(raw_body: bytes, signature: str) -> None:
    secret = os.getenv("BREACHFORGE_WEBHOOK_SECRET")
    if not secret:
        return
    expected = hmac.new(key=secret.encode(), msg=raw_body, digestmod=hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook signature")


def _build_scan_create_payload(target_url: str, gate_config: dict[str, Any] | None) -> ScanCreate:
    payload: dict[str, Any] = {
        "target_url": target_url,
        "unauth_mode": True,
    }
    if gate_config:
        v2_keys = {"scope", "method_classes", "destructive_budget", "time_windows", "version"}
        if any(key in gate_config for key in v2_keys):
            payload["policy_v2"] = gate_config
        else:
            payload["policy"] = gate_config
    try:
        return ScanCreate.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.errors()) from exc


@router.post("/trigger", response_model=WebhookTriggerResponse)
async def trigger_webhook_scan(
    request: Request,
    body: WebhookTriggerRequest,
    db: AsyncSession = Depends(get_db),
    x_bf_signature: str | None = Header(default=None, alias="X-BF-Signature"),
) -> WebhookTriggerResponse:
    signature = x_bf_signature or body.signature
    if signature:
        _validate_signature(await request.body(), signature)

    scan_payload = _build_scan_create_payload(body.target_url, body.gate_config)
    scan_response = await create_scan(scan_payload, db)
    status_url = str(request.url_for("get_scan", scan_id=scan_response.id))

    logger.info("ci_webhook_triggered", source=body.source)
    return WebhookTriggerResponse(scan_id=scan_response.id, status_url=status_url, source=body.source)


@router.get("/health")
async def webhook_health() -> dict[str, str]:
    return {"status": "ok"}
