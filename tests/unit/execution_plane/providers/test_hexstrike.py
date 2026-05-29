from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from execution_plane.providers.hexstrike import HexStrikeProvider


@pytest.mark.asyncio
async def test_health_check_true_on_200() -> None:
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = httpx.Response(200)
    provider = HexStrikeProvider(client=client)

    assert await provider.health_check() is True


@pytest.mark.asyncio
async def test_health_check_false_on_connect_error() -> None:
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = httpx.ConnectError("connection failed")
    provider = HexStrikeProvider(client=client)

    assert await provider.health_check() is False


@pytest.mark.asyncio
async def test_run_dispatches_correct_post_url() -> None:
    client = AsyncMock(spec=httpx.AsyncClient)
    response = Mock()
    response.text = '{"ok": true}'
    response.json.return_value = {"ok": True}
    response.raise_for_status.return_value = None
    client.post.return_value = response
    provider = HexStrikeProvider(base_url="http://localhost:8888", client=client)

    result = await provider.run(
        {"tool": "zap", "target": "https://example.com", "args": {"a": 1}},
        {},
    )

    client.post.assert_awaited_once_with(
        "http://localhost:8888/tools/zap",
        json={"target": "https://example.com", "args": {"a": 1}},
    )
    assert result.exit_code == 0
    assert result.provider_id == "hexstrike"


@pytest.mark.asyncio
async def test_run_raises_value_error_for_unknown_tool() -> None:
    provider = HexStrikeProvider(client=AsyncMock(spec=httpx.AsyncClient))

    with pytest.raises(ValueError):
        await provider.run({"tool": "unknown"}, {})


@pytest.mark.asyncio
async def test_run_returns_failure_toolresult_on_http_error() -> None:
    client = AsyncMock(spec=httpx.AsyncClient)
    client.post.side_effect = httpx.HTTPError("request failed")
    provider = HexStrikeProvider(client=client)

    result = await provider.run({"tool": "zap", "target": "https://example.com"}, {})

    assert result.exit_code == 1
    assert result.provider_id == "hexstrike"
    assert result.stdout == ""
    assert "request failed" in result.stderr
    assert result.json_output is None


@pytest.mark.asyncio
async def test_provider_id_is_hexstrike_in_all_toolresults() -> None:
    success_client = AsyncMock(spec=httpx.AsyncClient)
    success_response = Mock()
    success_response.text = "ok"
    success_response.json.return_value = {"ok": True}
    success_response.raise_for_status.return_value = None
    success_client.post.return_value = success_response

    success_provider = HexStrikeProvider(client=success_client)
    success_result = await success_provider.run({"tool": "zap", "target": "https://example.com"}, {})

    fail_client = AsyncMock(spec=httpx.AsyncClient)
    fail_client.post.side_effect = httpx.HTTPError("boom")
    fail_provider = HexStrikeProvider(client=fail_client)
    fail_result = await fail_provider.run({"tool": "zap", "target": "https://example.com"}, {})

    assert success_result.provider_id == "hexstrike"
    assert fail_result.provider_id == "hexstrike"
