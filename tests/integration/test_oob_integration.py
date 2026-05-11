from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from execution_plane.oob.oob_manager import OOBConfig, OOBManager
from execution_plane.validator.strategies.ssrf import SsrfStrategy as SSRFStrategy
from storage.db.models import RawProbe


def _probe(
    *,
    request: dict[str, object],
    response: dict[str, object],
    attack_task_id=None,
) -> RawProbe:
    return RawProbe(
        id=uuid4(),
        attack_task_id=attack_task_id or uuid4(),
        worker_id="worker-test",
        timestamp=datetime.now(UTC),
        request=request,
        response=response,
        control_probe_id=None,
    )


@pytest.mark.asyncio
async def test_ssrf_with_oob_hit_generates_092_confidence() -> None:
    config = OOBConfig(oob_enabled=True, base_url="http://test.oob", ttl_seconds=5)
    mock_redis = MagicMock()
    mock_redis.get.return_value = json.dumps(
        {
            "probe_token": "generated-by-manager",
            "hit_type": "http",
            "source_ip": "192.0.2.10",
            "payload": {"path": "/scan-test/generated-by-manager"},
        }
    )
    manager = OOBManager(redis_client=mock_redis, config=config)
    strategy = SSRFStrategy()
    attack_probe = _probe(
        request={
            "method": "GET",
            "url": "https://app.example.test/fetch?url=...",
            "ssrf_target_url": "http://10.0.0.2/",
            "ssrf_allowlist": ["test.oob"],
            "baseline_latency_ms": 100,
            "scan_id": "scan-test",
        },
        response={"status": 504, "body": "", "latency_ms": 3200},
    )

    result = await strategy.validate(
        attack_probe=attack_probe,
        control_probe=None,
        oob_manager=manager,
    )

    assert result is not None
    assert result.confidence_score == 0.92
    assert mock_redis.setex.call_count == 1
    assert mock_redis.get.call_count == 1
    hit_key = mock_redis.get.call_args.args[0]
    assert hit_key.startswith("oob:hit:")


@pytest.mark.asyncio
async def test_ssrf_without_oob_manager_uses_default_confidence() -> None:
    strategy = SSRFStrategy()
    attack_probe = _probe(
        request={
            "method": "GET",
            "url": "https://app.example.test/fetch?url=...",
            "ssrf_target_url": "http://10.0.0.2/",
            "baseline_latency_ms": 100,
        },
        response={"status": 504, "body": "", "latency_ms": 3200},
    )

    result = await strategy.validate(
        attack_probe=attack_probe,
        control_probe=None,
        oob_manager=None,
    )

    assert result is None or result.confidence_score <= 0.65
