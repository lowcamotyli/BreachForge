from __future__ import annotations

from starlette.testclient import TestClient

from .lab_app import app, reset_state


client = TestClient(app)


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_login_returns_token() -> None:
    reset_state()
    response = client.post("/api/auth/login", json={"username": "alice", "password": "alice123"})
    assert response.status_code == 200
    assert response.json()["token"] == "tok_sh_alice"


def test_public_endpoint_no_auth() -> None:
    reset_state()
    response = client.get("/api/users")
    assert response.status_code == 200


def test_js_contains_endpoints() -> None:
    reset_state()
    response = client.get("/static/app.js")
    body = response.text
    assert response.status_code == 200
    assert "/api/admin/stats" in body
    assert "/api/internal/metrics" in body


def test_bfla_present() -> None:
    reset_state()
    response = client.get("/api/admin/stats", headers=_auth_header("tok_sh_alice"))
    assert response.status_code != 403


def test_hidden_endpoint_no_auth() -> None:
    reset_state()
    response = client.get("/api/internal/metrics")
    assert response.status_code == 200
