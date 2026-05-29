from __future__ import annotations

from starlette.testclient import TestClient

from .lab_app import app, reset_state


client = TestClient(app)


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_login_returns_token() -> None:
    reset_state()
    response = client.post("/auth/login", json={"username": "alice", "password": "alice123"})
    assert response.status_code == 200
    assert response.json()["token"] == "tok_ao_alice"


def test_expired_token_reuse() -> None:
    reset_state()
    response = client.get("/api/profile", headers=_auth_header("tok_ao_expired"))
    assert response.status_code == 200


def test_logout_reuse() -> None:
    reset_state()
    login = client.post("/auth/login", json={"username": "alice", "password": "alice123"})
    token = login.json()["token"]
    logout = client.post("/auth/logout", headers=_auth_header(token))
    assert logout.status_code == 200
    response = client.get("/api/data", headers=_auth_header(token))
    assert response.status_code == 200


def test_oauth_state_csrf() -> None:
    reset_state()
    response = client.get("/oauth/callback?code=x&state=random_unregistered_state")
    assert response.status_code == 200


def test_redirect_manipulation() -> None:
    reset_state()
    response = client.get("/oauth/authorize?client_id=app&redirect_uri=https://evil.com/steal&state=abc")
    assert response.status_code == 200
    assert "evil.com" in response.json()["authorize_url"]


def test_auth_expired_always_401() -> None:
    reset_state()
    response = client.get("/auth/expired")
    assert response.status_code == 401
    assert response.json() == {"error": "session_expired"}


def test_auth_logout_blacklisted_session_returns_401_on_subsequent_request() -> None:
    reset_state()
    headers = {"Cookie": "session=session-abc-123"}
    first = client.post("/auth/logout", headers=headers)
    assert first.status_code == 200
    follow_up = client.get("/auth/session-check", headers=headers)
    assert follow_up.status_code == 401
    assert follow_up.json() == {"error": "session_revoked"}


def test_auth_role_check_mismatch_and_admin_success() -> None:
    reset_state()
    denied = client.get("/auth/role-check")
    assert denied.status_code == 403
    assert denied.json() == {"error": "insufficient_role"}
    allowed = client.get("/auth/role-check", headers={"X-Role": "admin"})
    assert allowed.status_code == 200


def test_auth_csrf_protected_requires_fixed_token() -> None:
    reset_state()
    denied = client.get("/auth/csrf-protected")
    assert denied.status_code == 403
    assert denied.json() == {"error": "csrf_failed"}
    allowed = client.get("/auth/csrf-protected", headers={"X-CSRF-Token": "test-csrf-token-abc123"})
    assert allowed.status_code == 200
