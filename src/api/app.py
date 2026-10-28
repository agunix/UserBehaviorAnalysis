"""
UBA :: API + Dashboard (FastAPI)
-------------------------------------
One process, one port: both JSON API and dashboard UI are provided from this application.

Endpoint-lər:
    GET /healthz        - process is alive (unauthenticated, only {"status": "ok"})
    GET /api/health     - Wazuh Indexer connection status
    GET /api/overview   - summary (KPI, timeline, top-N) + latest events
    GET /               - dashboard (index.html)
    GET /ui/app.js|css  - UI aktivləri (yalnız whitelist)

Authentication: `api.basic_password` is set, all endpoints are protected (except /healthz)
HTTP Basic authentication is required. Default bind address is 127.0.0.1. If you expose it to the network, set a password
and use a reverse proxy (nginx/caddy) for TLS - Basic Auth transmits the password in clear text over HTTP.

Running:
    python main.py
    (or) uvicorn src.api.app:create_app --factory --host 127.0.0.1 --port 8088
"""

from __future__ import annotations

import logging
import secrets
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from src.api.service import EventService, IndexerUnavailable
from src.config.config import get_settings

logger = logging.getLogger("aiuba.api")

VERSION = "0.1.0"
UI_DIR = Path(__file__).resolve().parent / "ui"
UI_ASSETS = {
    "app.js": "text/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
}

# The UI displays log content that could be under the attacker's control (username, command line...).
# Therefore, inline scripts/styles are prohibited; only same-origin files are allowed.
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def create_app(service: Optional[EventService] = None, settings=None) -> FastAPI:
    settings = settings or get_settings()
    service = service or EventService(settings)
    api_cfg = settings.api

    if api_cfg.host not in _LOCAL_HOSTS and not api_cfg.basic_password:
        logger.warning(
            "API %s open with unauthenticated access! Assign api.basic_password to enable authentication "
            "or bind to 127.0.0.1 and use a reverse proxy.",
            api_cfg.host,
        )

    security = HTTPBasic(auto_error=False)

    def require_auth(credentials: Optional[HTTPBasicCredentials] = Depends(security)) -> None:
        if not api_cfg.basic_password:
            return
        user_ok = pass_ok = False
        if credentials is not None:
            user_ok = secrets.compare_digest(
                credentials.username.encode("utf-8"), api_cfg.basic_user.encode("utf-8")
            )
            pass_ok = secrets.compare_digest(
                credentials.password.encode("utf-8"), api_cfg.basic_password.encode("utf-8")
            )
        if not (user_ok and pass_ok):
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": 'Basic realm="AI-UBA"'},
            )

    app = FastAPI(
        title="AI-UBA",
        version=VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    router = APIRouter(dependencies=[Depends(require_auth)])

    @router.get("/api/health")
    def health():
        indexer = service.check_indexer()
        return {
            "status": "ok" if indexer.get("ok") else "degraded",
            "version": VERSION,
            "indexer": indexer,
        }

    @router.get("/api/overview")
    def overview(
        minutes: int = Query(60, ge=5, le=10080, description="Last n minutes (5 - 10080)"),
        source: Literal["all", "windows", "linux"] = "all",
        limit: int = Query(200, ge=1, le=1000, description="Number of events to display in the table"),
    ):
        try:
            return service.overview(minutes=minutes, source=source, limit=limit)
        except IndexerUnavailable as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @router.get("/")
    def index():
        return FileResponse(UI_DIR / "index.html", media_type="text/html; charset=utf-8")

    @router.get("/ui/{name}")
    def ui_asset(name: str):
        media_type = UI_ASSETS.get(name)
        if media_type is None:
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(UI_DIR / name, media_type=media_type)

    app.include_router(router)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):  # pragma: no cover - last defense, should not happen
        logger.exception("Unanticipated error: %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return app
