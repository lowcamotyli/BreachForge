from __future__ import annotations

from execution_plane.validator.secret_leak_source import SecretLeakSource, SecretLeakSourceClassifier


def _classify(
    *,
    url: str = "",
    response_content_type: str = "",
    response_body: str = "",
    found_in_response_headers: bool = False,
):
    return SecretLeakSourceClassifier().classify(
        url=url,
        response_content_type=response_content_type,
        response_body=response_body,
        found_in_response_headers=found_in_response_headers,
    )


def test_classifies_debug_endpoint_from_url() -> None:
    result = _classify(url="https://example.test/debug/status")

    assert result.source is SecretLeakSource.DEBUG_ENDPOINT
    assert result.confidence == 1.0


def test_classifies_source_map_from_url() -> None:
    result = _classify(url="https://example.test/static/app.js.map")

    assert result.source is SecretLeakSource.SOURCE_MAP
    assert result.confidence == 1.0


def test_classifies_config_json_from_config_url() -> None:
    result = _classify(url="https://example.test/config")

    assert result.source is SecretLeakSource.CONFIG_JSON
    assert result.confidence == 0.95


def test_classifies_public_asset_from_api_docs_url() -> None:
    result = _classify(url="https://example.test/api-docs")

    assert result.source is SecretLeakSource.PUBLIC_ASSET
    assert result.confidence == 0.9


def test_classifies_response_header_when_found_in_headers() -> None:
    result = _classify(found_in_response_headers=True)

    assert result.source is SecretLeakSource.RESPONSE_HEADER
    assert result.confidence == 0.95


def test_classifies_stack_trace_from_body() -> None:
    result = _classify(response_body="Exception in application startup")

    assert result.source is SecretLeakSource.STACK_TRACE
    assert result.confidence == 0.9


def test_classifies_config_json_from_json_body_keywords() -> None:
    result = _classify(
        response_content_type="application/json",
        response_body='{"database_url":"postgres://example"}',
    )

    assert result.source is SecretLeakSource.CONFIG_JSON
    assert result.confidence == 0.9


def test_defaults_to_response_body() -> None:
    result = _classify(response_body="api_key exposed in non-json response")

    assert result.source is SecretLeakSource.RESPONSE_BODY
    assert result.confidence == 0.7


def test_unknown_source_is_part_of_contract() -> None:
    assert SecretLeakSource.UNKNOWN.value == "unknown"


def test_url_overrides_body_classification() -> None:
    result = _classify(
        url="https://example.test/debug/status",
        response_body="Traceback with secret_key detail",
    )

    assert result.source is SecretLeakSource.DEBUG_ENDPOINT
    assert result.confidence == 1.0


def test_response_header_overrides_body_classification() -> None:
    result = _classify(
        response_body="Traceback with password detail",
        found_in_response_headers=True,
    )

    assert result.source is SecretLeakSource.RESPONSE_HEADER
    assert result.confidence == 0.95


def test_confidence_values_are_in_range() -> None:
    scenarios = [
        _classify(url="https://example.test/debug/status"),
        _classify(url="https://example.test/app.map"),
        _classify(url="https://example.test/config"),
        _classify(url="https://example.test/swagger"),
        _classify(url="https://example.test/assets/app.js"),
        _classify(found_in_response_headers=True),
        _classify(response_body="Stack trace follows"),
        _classify(response_content_type="application/json", response_body='{"token":"redacted"}'),
        _classify(),
    ]

    assert all(0.0 <= result.confidence <= 1.0 for result in scenarios)
