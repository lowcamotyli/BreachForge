from __future__ import annotations

import asyncio

import structlog

from execution_plane.oob.oob_manager import OOBManager

logger = structlog.get_logger(__name__)


class DNSMonitor:
    def __init__(self, oob_manager: OOBManager, dns_enabled: bool = False) -> None:
        self.oob_manager = oob_manager
        self.dns_enabled = dns_enabled
        self._running = False

    async def start(self) -> None:
        if not self.dns_enabled:
            logger.info("dns_monitor_disabled")
            return

        self._running = True
        logger.info("dns_monitor_started", wildcard="*.oob.breachforge.internal")
        while self._running:
            await asyncio.sleep(0.5)

    async def stop(self) -> None:
        self._running = False
        logger.info("dns_monitor_stopped")

    async def _process_dns_hit(self, probe_token: str, source_ip: str) -> None:
        self.oob_manager.register_hit(
            probe_token=probe_token,
            hit_type="dns",
            source_ip=source_ip,
            payload={"type": "dns_lookup"},
        )

    async def simulate_dns_hit(self, probe_token: str, source_ip: str) -> None:
        await self._process_dns_hit(probe_token=probe_token, source_ip=source_ip)
