from __future__ import annotations

from starlette.testclient import TestClient

from tests.benchmark_lab.labs.graphql.lab_app import app, reset_state


client = TestClient(app)


def _auth_headers(token: str = "tok_gql_alice") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def setup_function() -> None:
    reset_state()


def test_introspection() -> None:
    response = client.post("/graphql", json={"query": "query { __schema { types { name } } }"})

    assert response.status_code == 200
    assert "types" in response.json()["data"]["__schema"]


def test_batch_queries() -> None:
    response = client.post(
        "/graphql",
        json=[{"query": "query{viewer{id}}"}, {"query": "query{viewer{id}}"}],
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert len(response.json()) == 2


def test_depth_query() -> None:
    response = client.post(
        "/graphql",
        json={"query": "query { user { orders { items { product { category { name } } } } } }"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["user"]["orders"][0]["items"][0]["product"]["category"]["name"] == "Electronics"


def test_field_auth_missing() -> None:
    response = client.post(
        "/graphql",
        json={"query": "query { adminConfig { secret maxUsers } }"},
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    assert response.json()["data"]["adminConfig"] == {"secret": "admin_secret_value", "maxUsers": 100}


def test_viewer_requires_auth() -> None:
    response = client.post("/graphql", json={"query": "query { viewer { id username role } }"})

    assert response.status_code == 401
