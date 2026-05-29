from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routers import inventory as inventory_module


def _inventory_client() -> TestClient:
    app = FastAPI()
    app.include_router(inventory_module.router)
    return TestClient(app)


def test_get_inventory_endpoints_returns_200_and_list() -> None:
    response = _inventory_client().get("/inventory/endpoints")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_inventory_services_returns_200_and_list() -> None:
    response = _inventory_client().get("/inventory/services")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_inventory_drift_returns_200_and_list() -> None:
    response = _inventory_client().get("/inventory/drift")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_inventory_endpoint_nonexistent_returns_404() -> None:
    response = _inventory_client().get("/inventory/endpoints/nonexistent")

    assert response.status_code == 404
