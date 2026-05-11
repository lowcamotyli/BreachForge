from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from api.middleware.logging import configure_logging
from api.routers import auth_check_router, findings_router, reports_router, scans_router, session_router

_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

configure_logging()


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(title="ProofScan API", version="0.1.0", lifespan=lifespan)

app.include_router(scans_router, prefix="/scans", tags=["scans"])
app.include_router(auth_check_router, prefix="/auth", tags=["auth"])
app.include_router(findings_router, tags=["findings"])
app.include_router(reports_router, tags=["reports"])
app.include_router(session_router)


@app.middleware("http")
async def no_store_frontend_html(request: Request, call_next) -> Response:
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/ui"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}


if _FRONTEND_DIR.exists():
    app.mount("/ui", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(
            _FRONTEND_DIR / "index.html",
            headers={
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
            },
        )
