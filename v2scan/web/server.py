"""FastAPI application factory and uvicorn launcher."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..core.singbox import kill_all
from .routes import STATIC_DIR, SessionManager, router

_LOCAL_HOSTS = ["localhost", "127.0.0.1", "[::1]", "::1", "testserver"]


def create_app(bind_host: str = "127.0.0.1") -> FastAPI:
    """Build the app. Host headers are restricted to loopback names (anti DNS-rebinding)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        manager: SessionManager = app.state.sessions
        manager.loop = asyncio.get_running_loop()
        yield
        await manager.shutdown()
        kill_all()

    app = FastAPI(title="V2Scan", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.sessions = SessionManager()

    wildcard = bind_host in ("0.0.0.0", "::")  # exposed on the LAN: any Host header is legitimate
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"] if wildcard else [*_LOCAL_HOSTS, bind_host],
    )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", ())[1:])
        return JSONResponse({"error": f"Invalid request: {where} {first.get('msg', '')}".strip()}, status_code=400)

    app.include_router(router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


class _Server(uvicorn.Server):
    """Cancels running scans on Ctrl+C so open SSE streams end and sing-box is cleaned up."""

    def __init__(self, config: uvicorn.Config, manager: SessionManager) -> None:
        super().__init__(config)
        self._manager = manager

    def handle_exit(self, sig: int, frame) -> None:  # noqa: ANN001
        loop = self._manager.loop
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(self._manager.begin_shutdown)
        super().handle_exit(sig, frame)


def run_server(host: str = "127.0.0.1", port: int = 8686) -> None:
    """Serve the dashboard until interrupted."""
    app = create_app(host)
    config = uvicorn.Config(
        app, host=host, port=port, log_level="warning", timeout_graceful_shutdown=5
    )
    try:
        _Server(config, app.state.sessions).run()
    finally:
        kill_all()
