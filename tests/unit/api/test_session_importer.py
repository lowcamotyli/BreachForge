from __future__ import annotations

import json

from fastapi.testclient import TestClient

from api.importers.session_importer import HarImporter, OpenApiImporter, PostmanImporter
from api.main import app


def test_har_importer_extracts_cookies_and_basic_auth() -> None:
    content = json.dumps(
        {
            "log": {
                "entries": [
                    {
                        "request": {
                            "cookies": [{"name": "sessionid", "value": "abc123"}],
                            "headers": [
                                {"name": "Authorization", "value": "Basic dXNlcjpwYXNz"},
                                {"name": "X-CSRF-Token", "value": "csrf-token"},
                            ],
                        }
                    }
                ]
            }
        }
    )

    material = HarImporter().extract_auth(content)

    assert material.source_format == "har"
    assert material.cookies == {"sessionid": "abc123"}
    assert material.headers["Authorization"] == "Basic dXNlcjpwYXNz"
    assert material.tokens["basic"] == "user:pass"
    assert material.tokens["X-CSRF-Token"] == "csrf-token"
    assert material.auth_type == "mixed"


def test_postman_importer_extracts_bearer_token() -> None:
    content = json.dumps(
        {
            "info": {
                "name": "Auth collection",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [
                {
                    "name": "Me",
                    "request": {
                        "method": "GET",
                        "header": [{"key": "Authorization", "value": "Bearer postman-token"}],
                        "url": "https://example.test/me",
                    },
                }
            ],
        }
    )

    material = PostmanImporter().extract_auth(content)

    assert material.source_format == "postman"
    assert material.headers["Authorization"] == "Bearer postman-token"
    assert material.tokens["bearer"] == "postman-token"
    assert material.auth_type == "bearer"


def test_openapi_importer_extracts_basic_auth_scheme() -> None:
    content = json.dumps(
        {
            "openapi": "3.0.3",
            "components": {
                "securitySchemes": {
                    "basicAuth": {
                        "type": "http",
                        "scheme": "basic",
                    }
                }
            },
        }
    )

    material = OpenApiImporter().extract_auth(content)

    assert material.source_format == "openapi"
    assert material.headers["Authorization"] == "Basic <basicAuth_credentials>"
    assert material.tokens["basic"] == "<basicAuth_credentials>"
    assert material.auth_type == "basic"


def test_openapi_importer_extracts_api_key_header() -> None:
    content = json.dumps(
        {
            "openapi": "3.0.3",
            "components": {
                "securitySchemes": {
                    "apiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key",
                    }
                }
            },
        }
    )

    material = OpenApiImporter().extract_auth(content)

    assert material.headers == {"X-API-Key": "<X-API-Key>"}
    assert material.tokens == {"X-API-Key": "<X-API-Key>"}
    assert material.auth_type == "api_key"


def test_sessions_import_endpoint_rejects_unsupported_format() -> None:
    client = TestClient(app)

    response = client.post(
        "/sessions/import",
        files={"file": ("unsupported.json", json.dumps({"items": []}), "application/json")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported session import format"
