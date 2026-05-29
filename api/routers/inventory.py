from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from api.models.responses import DriftItemResponse, InventoryEndpointResponse, InventoryServiceResponse

router = APIRouter(prefix="/inventory", tags=["inventory"])


@router.get("/endpoints", response_model=list[InventoryEndpointResponse])
async def list_inventory_endpoints() -> list[InventoryEndpointResponse]:
    return []


@router.get("/endpoints/{endpoint_id}", response_model=InventoryEndpointResponse)
async def get_inventory_endpoint(endpoint_id: str) -> InventoryEndpointResponse:
    del endpoint_id
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")


@router.get("/services", response_model=list[InventoryServiceResponse])
async def list_inventory_services() -> list[InventoryServiceResponse]:
    return []


@router.get("/drift", response_model=list[DriftItemResponse])
async def list_inventory_drift() -> list[DriftItemResponse]:
    return []
