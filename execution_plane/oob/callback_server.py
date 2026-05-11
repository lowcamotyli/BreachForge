from __future__ import annotations

from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI, Request

from execution_plane.oob.oob_manager import OOBManager

logger = structlog.get_logger(__name__)


class CallbackServer:
    def __init__(self, oob_manager: OOBManager, host: str = "0.0.0.0", port: int = 8888) -> None:
        self.oob_manager = oob_manager
        self.host = host
        self.port = port
        self.app = FastAPI()
        self._register_routes()

    def _register_routes(self) -> None:
        @self.app.get("/callback/{scan_id}/{probe_token}")
        @self.app.post("/callback/{scan_id}/{probe_token}")
        async def callback(scan_id: str, probe_token: str, request: Request) -> dict[str, Any]:
            body = (await request.body()).decode()
            source_ip = request.client.host if request.client else ""
            self.oob_manager.register_hit(
                probe_token=probe_token,
                hit_type="http",
                source_ip=source_ip,
                payload={
                    "method": request.method,
                    "headers": dict(request.headers),
                    "body": body,
                },
            )
            return {"status": "ok", "probe_token": probe_token}

    async def start(self) -> None:
        config = uvicorn.Config(app=self.app, host=self.host, port=self.port)
        server = uvicorn.Server(config)
        logger.info("oob_callback_server_starting", host=self.host, port=self.port)
        await server.serve()
