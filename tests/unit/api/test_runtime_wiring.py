from __future__ import annotations

import os
import subprocess
import sys

from fastapi.testclient import TestClient

from api.main import app


def test_health_does_not_require_database_url() -> None:
    script = """
import os
os.environ.pop("DATABASE_URL", None)
from fastapi.testclient import TestClient
from api.main import app
response = TestClient(app).get("/health")
assert response.status_code == 200
assert response.json()["status"] == "ok"
"""
    env = os.environ.copy()
    env.pop("DATABASE_URL", None)

    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_recon_routes_are_visible_in_openapi() -> None:
    schema = TestClient(app).get("/openapi.json").json()

    assert "/recon/har" in schema["paths"]
    assert "/recon/spec" in schema["paths"]
