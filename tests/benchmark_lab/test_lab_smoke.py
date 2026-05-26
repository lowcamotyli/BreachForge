from __future__ import annotations

from starlette.testclient import TestClient

from tests.benchmark_lab.lab_app import app, reset_state


client = TestClient(app)


def _login(username: str, password: str) -> str:
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["token"]


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_login_returns_token() -> None:
    reset_state()
    response = client.post("/auth/login", json={"username": "alice", "password": "alice123"})
    assert response.status_code == 200
    body = response.json()
    assert "token" in body


def test_bola_vuln_present() -> None:
    reset_state()
    token = _login("carol", "carol123")
    response = client.get("/users/alice", headers=_auth_headers(token))
    assert response.status_code == 200


def test_bfla_vuln_present() -> None:
    reset_state()
    token = _login("alice", "alice123")
    response = client.post("/admin/orders/order-1/approve", headers=_auth_headers(token))
    assert response.status_code != 403


def test_tenant_isolation_vuln() -> None:
    reset_state()
    token = _login("carol", "carol123")
    response = client.get("/orders/order-1", headers=_auth_headers(token))
    assert response.status_code == 200


def test_priv_esc_vuln() -> None:
    reset_state()
    token = _login("alice", "alice123")
    response = client.patch("/users/alice/profile", json={"role": "admin"}, headers=_auth_headers(token))
    assert response.status_code == 200
    assert response.json()["role"] == "admin"


def test_auth_bypass_expired() -> None:
    reset_state()
    response = client.post("/jobs/export", headers=_auth_headers("tok_expired"))
    assert response.status_code == 200


def test_graphql_endpoint() -> None:
    reset_state()
    token = _login("alice", "alice123")
    response = client.post(
        "/graphql",
        json={"query": "query { viewer { id username role } }"},
        headers=_auth_headers(token),
    )
    assert response.status_code == 200
    body = response.json()
    assert "data" in body
    assert "viewer" in body["data"]
