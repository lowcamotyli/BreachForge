from __future__ import annotations

from starlette.testclient import TestClient

from .lab_app import app, reset_state


client = TestClient(app)


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_login_returns_token() -> None:
    reset_state()
    response = client.post("/api/v1/auth/login", json={"username": "alice", "password": "alice123"})
    assert response.status_code == 200
    assert response.json()["token"] == "tok_as_alice"


def test_bola_present() -> None:
    reset_state()
    response = client.get("/api/v1/resources/res-3", headers=_auth_header("tok_as_alice"))
    assert response.status_code == 200


def test_bfla_present() -> None:
    reset_state()
    response = client.post("/api/v1/admin/bulk-export", headers=_auth_header("tok_as_alice"))
    assert response.status_code != 403


def test_hidden_endpoint_present() -> None:
    reset_state()
    response = client.get("/api/v1/internal/debug")
    assert response.status_code == 200


def test_tenant_isolation_present() -> None:
    reset_state()
    response = client.get("/api/v1/workspaces/ws-2/data", headers=_auth_header("tok_as_alice"))
    assert response.status_code == 200


def test_mass_assignment_present() -> None:
    reset_state()
    response = client.patch(
        "/api/v1/users/me",
        json={"is_admin": True},
        headers=_auth_header("tok_as_alice"),
    )
    assert response.status_code == 200
    assert response.json()["is_admin"] is True


def test_openapi_spec_missing_internal() -> None:
    reset_state()
    response = client.get("/api/v1/openapi-spec")
    assert response.status_code == 200
    assert "/api/v1/internal/debug" not in response.json()["documented_endpoints"]
