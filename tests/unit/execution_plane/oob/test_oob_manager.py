from __future__ import annotations

import json
import re
from unittest.mock import MagicMock

import pytest

from execution_plane.oob.oob_manager import OOBConfig, OOBManager


UUID4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _manager(redis_client: MagicMock | None = None) -> OOBManager:
    active_redis = redis_client or MagicMock()
    active_redis.get.return_value = None
    return OOBManager(active_redis, OOBConfig(base_url="https://oob.example.test"))


def test_generate_callback_url_returns_unique_tokens() -> None:
    manager = _manager()

    _, first_token = manager.generate_callback_url("scan-123")
    _, second_token = manager.generate_callback_url("scan-123")

    assert first_token != second_token


def test_generate_callback_url_url_contains_scan_id() -> None:
    manager = _manager()

    url, _ = manager.generate_callback_url("scan-123")

    assert "scan-123" in url


@pytest.mark.asyncio
async def test_register_and_wait_for_hit() -> None:
    redis_client = MagicMock()
    redis_client.get.return_value = None
    manager = _manager(redis_client)
    payload = {"endpoint": "/api/probe"}

    manager.register_hit(
        probe_token="probe-token",
        hit_type="http",
        source_ip="192.0.2.10",
        payload=payload,
    )
    redis_client.get.return_value = json.dumps(
        {
            "probe_token": "probe-token",
            "hit_type": "http",
            "source_ip": "192.0.2.10",
            "payload": payload,
        }
    ).encode()

    hit = await manager.wait_for_hit("probe-token", timeout=0.1)

    assert hit == {
        "probe_token": "probe-token",
        "hit_type": "http",
        "source_ip": "192.0.2.10",
        "payload": payload,
    }


@pytest.mark.asyncio
async def test_wait_for_hit_returns_none_on_timeout() -> None:
    manager = _manager()

    hit = await manager.wait_for_hit("missing-token", timeout=0.1)

    assert hit is None


def test_oob_disabled_by_default() -> None:
    assert OOBConfig().oob_enabled is False


def test_probe_token_is_uuid() -> None:
    manager = _manager()

    _, probe_token = manager.generate_callback_url("scan-123")

    assert UUID4_PATTERN.match(probe_token)
