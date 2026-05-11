from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import yaml
from fastapi import APIRouter, File, HTTPException, UploadFile, status
from pydantic import BaseModel

from execution_plane.crawler.har_importer import HarImporter
from execution_plane.crawler.spec_importer import SpecImporter

router = APIRouter(prefix="/recon", tags=["recon"])


class ReconHarResponse(BaseModel):
    asset_count: int
    endpoint_count: int
    identity_found: bool
    cookie_count: int
    body_schema_hints: int


class ReconSpecResponse(BaseModel):
    format: str
    endpoint_count: int
    auth_hints_count: int
    path_count: int


def _count_har_body_schema_hints(asset_map: Any) -> int:
    count = 0
    for endpoint in asset_map.endpoints:
        has_body_schema = any(
            isinstance(parameter, Mapping) and bool(parameter.get("body_schema"))
            for parameter in endpoint.parameters
        )
        if has_body_schema:
            count += 1
    return count


def _count_spec_paths(asset_map: Any) -> int:
    return len({endpoint.url_pattern for endpoint in asset_map.endpoints})


def _detect_spec_format(spec: Mapping[str, Any]) -> str:
    if "openapi" in spec or "swagger" in spec:
        return "openapi"

    info = spec.get("info")
    if isinstance(info, Mapping):
        schema = info.get("schema")
        if isinstance(schema, str) and "v2.1" in schema:
            return "postman"

    if spec.get("__export_format") == 4:
        return "insomnia"

    return "unknown"


@router.post("/har", response_model=ReconHarResponse)
async def import_har(file: UploadFile = File(...)) -> ReconHarResponse:
    raw = await file.read()

    try:
        parsed_json = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid HAR JSON") from exc

    if not isinstance(parsed_json, Mapping) or not isinstance(parsed_json.get("log"), Mapping):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid HAR format")

    try:
        asset_map, session_snapshot = HarImporter().parse(dict(parsed_json))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid HAR: {exc}") from exc

    hosts = {
        parsed.hostname
        for endpoint in asset_map.endpoints
        if (parsed := urlparse(endpoint.url_pattern)).hostname
    }

    cookies = session_snapshot.cookies if session_snapshot is not None else []

    return ReconHarResponse(
        asset_count=len(hosts),
        endpoint_count=len(asset_map.endpoints),
        identity_found=session_snapshot is not None,
        cookie_count=len(cookies),
        body_schema_hints=_count_har_body_schema_hints(asset_map),
    )


@router.post("/spec", response_model=ReconSpecResponse)
async def import_spec(file: UploadFile = File(...)) -> ReconSpecResponse:
    raw = await file.read()
    parsed_data: dict[str, Any] | None = None

    try:
        candidate = json.loads(raw)
        if isinstance(candidate, Mapping):
            parsed_data = dict(candidate)
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed_data = None

    if parsed_data is None:
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid spec encoding") from exc

        try:
            candidate = yaml.safe_load(decoded)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid YAML spec") from exc

        if isinstance(candidate, Mapping):
            parsed_data = dict(candidate)

    if parsed_data is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid specification payload")

    detected_format = _detect_spec_format(parsed_data)

    try:
        asset_map = SpecImporter().parse(parsed_data)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Specification parse failed: {exc}") from exc

    if detected_format == "unknown":
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unrecognized specification format")

    auth_hints = getattr(asset_map, "auth_hints", [])
    auth_hints_count = len(auth_hints) if isinstance(auth_hints, list) else 0

    return ReconSpecResponse(
        format=detected_format,
        endpoint_count=len(asset_map.endpoints),
        auth_hints_count=auth_hints_count,
        path_count=_count_spec_paths(asset_map),
    )
