from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class OOBConfig:
    oob_enabled: bool = False
    base_url: str = ""
    listener_host: str = "0.0.0.0"
    listener_port: int = 8888
    dns_enabled: bool = False
    ttl_seconds: int = 30


class OOBManager:
    def __init__(self, redis_client: Any, config: OOBConfig) -> None:
        self.redis_client = redis_client
        self.config = config

    def generate_callback_url(self, scan_id: str, probe_token: str | None = None) -> tuple[str, str]:
        token = probe_token or str(uuid.uuid4())
        pending_key = f"oob:pending:{token}"
        pending_payload = {
            "scan_id": scan_id,
            "probe_token": token,
            "status": "pending",
        }
        self.redis_client.setex(pending_key, self.config.ttl_seconds, json.dumps(pending_payload))
        url = f"{self.config.base_url}/{scan_id}/{token}"
        return url, token

    def register_hit(self, probe_token: str, hit_type: str, source_ip: str, payload: dict) -> None:
        hit_key = f"oob:hit:{probe_token}"
        hit_payload = {
            "probe_token": probe_token,
            "hit_type": hit_type,
            "source_ip": source_ip,
            "payload": payload,
        }
        self.redis_client.set(hit_key, json.dumps(hit_payload))
        logger.info("oob_hit_registered", probe_token=probe_token, hit_type=hit_type, source_ip=source_ip)

    async def wait_for_hit(self, probe_token: str, timeout: float = 30.0) -> dict | None:
        hit_key = f"oob:hit:{probe_token}"
        deadline = asyncio.get_event_loop().time() + timeout

        while asyncio.get_event_loop().time() < deadline:
            raw_hit = self.redis_client.get(hit_key)
            if raw_hit:
                if isinstance(raw_hit, bytes):
                    raw_hit = raw_hit.decode()
                return json.loads(raw_hit)
            await asyncio.sleep(0.5)

        return None
