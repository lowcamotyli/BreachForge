from __future__ import annotations

import os

from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/proofscan")

from api.main import app


def test_verify_auth_context_valid() -> None:
    client = TestClient(app)

    response = client.post(
        "/auth/verify",
        json={
            "type": "token",
            "bearer_token": "token-value",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True


def test_verify_auth_context_invalid() -> None:
    client = TestClient(app)

    response = client.post(
        "/auth/verify",
        json={
            "type": "credential",
            "credentials": {"username": "", "password": ""},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
