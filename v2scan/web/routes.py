"""REST + SSE endpoints and the scan-session runner."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from ..core.config import DEFAULT_PROBE, DEFAULT_SINGBOX, GITHUB_CONFIG_SOURCES
from ..core.dedup import dedup_links
from ..core.models import ScanSession
from ..core.parsers import extract_proxy_links, get_protocol, parse_link
from ..core.singbox import SingBoxInfo, ensure_singbox
from ..core.tester import LatencyTester
from ..services.fetcher import fetch_sources, fetch_url

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_SESSIONS = 20
MAX_QR_BYTES = 2500

router = APIRouter()


# ─── Request models ─────────────────────────────────────────────────────────

class ScanSettings(BaseModel):
    parallel: int = Field(5, ge=1, le=200)
    timeout: int = Field(15, ge=1, le=120)
    startup_wait: float = Field(2.0, ge=0.1, le=60)
    batch_size: int = Field(40, ge=1, le=200)
    singbox_path: str = Field(DEFAULT_SINGBOX, max_length=500)
    probe_url: str = Field(DEFAULT_PROBE, max_length=2000)


class StartRequest(BaseModel):
    configs: str = Field(..., max_length=20_000_000)
    settings: ScanSettings = Field(default_factory=ScanSettings)


class CancelRequest(BaseModel):
    session_id: str


class FetchUrlRequest(BaseModel):
    url: str = Field(..., max_length=2000)
    timeout: float = Field(15, ge=1, le=120)


class FetchGithubRequest(BaseModel):
    timeout: float = Field(20, ge=1, le=120)


# ─── Session management ─────────────────────────────────────────────────────

class SessionManager:
    """Owns all web scan sessions and their background tasks."""

    def __init__(self) -> None:
        self.sessions: dict[str, ScanSession] = {}
        self.loop: asyncio.AbstractEventLoop | None = None

    def create(self, links: list[str], settings: ScanSettings) -> ScanSession:
        self._evict()
        sid = secrets.token_urlsafe(8)
        session = ScanSession(sid, links, settings.model_dump())
        for link in links:
            session.protocol_counts[get_protocol(link)] += 1
        self.sessions[sid] = session
        return session

    def get(self, sid: str) -> ScanSession:
        session = self.sessions.get(sid)
        if session is None:
            raise HTTPException(404, detail="Session not found")
        return session

    def _evict(self) -> None:
        """Drop the oldest finished sessions once the cap is reached."""
        while len(self.sessions) >= MAX_SESSIONS:
            victim = next(
                (sid for sid, s in self.sessions.items() if s.finished), None)
            if victim is None:
                return
            del self.sessions[victim]

    def begin_shutdown(self) -> None:
        for session in self.sessions.values():
            session.cancel()

    async def shutdown(self) -> None:
        self.begin_shutdown()
        tasks = [s.task for s in self.sessions.values() if s.task]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


def get_manager(request: Request) -> SessionManager:
    return request.app.state.sessions


async def run_session(session: ScanSession, info: SingBoxInfo) -> None:
    """Run a scan to completion (or cancellation), publishing events as results arrive."""
    cfg = session.settings
    stats = session.stats
    stats.start()
    session.running = True
    session.push_event("started", session.get_stats())

    def on_result(result) -> None:
        session.results.append(result)
        stats.record(result)
        session.push_event("result", result.to_event())
        session.push_event("stats", session.get_stats())

    tester = LatencyTester(
        info,
        probe=cfg["probe_url"],
        timeout=cfg["timeout"],
        startup_wait=cfg["startup_wait"],
        parallel=cfg["parallel"],
        batch_size=cfg["batch_size"],
        on_start=stats.mark_testing,
        on_result=on_result,
    )
    try:
        await tester.run(session.links)
    except asyncio.CancelledError:
        session.cancelled = True  # sing-box processes were already cleaned up by the tester
    except Exception as exc:
        session.push_event("error", {"message": f"Scan failed: {exc}"})
    finally:
        session.running = False
        session.finished = True
        session.push_event("finished", session.get_stats())


# ─── Pages ──────────────────────────────────────────────────────────────────

@router.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


# ─── Scan lifecycle ─────────────────────────────────────────────────────────

@router.post("/api/start")
async def start(body: StartRequest, request: Request) -> dict[str, Any]:
    links = extract_proxy_links(body.configs)
    if not links:
        raise HTTPException(400, detail="No valid configs found")

    singbox_path = body.settings.singbox_path
    if not Path(singbox_path).stem.lower().startswith("sing-box"):
        raise HTTPException(
            400, detail="singbox_path must point to a sing-box binary")
    probe_scheme = urlsplit(body.settings.probe_url).scheme
    if probe_scheme not in ("http", "https"):
        raise HTTPException(400, detail="probe_url must be http(s)")
    info = await ensure_singbox(singbox_path)
    if info is None:
        raise HTTPException(
            400, detail=f"sing-box not found or not runnable: {singbox_path}")

    manager = get_manager(request)
    session = manager.create(links, body.settings)
    session.task = asyncio.create_task(run_session(session, info))
    return {
        "session_id": session.session_id,
        "total": len(links),
        "protocols": dict(session.protocol_counts),
    }


@router.post("/api/cancel")
async def cancel(body: CancelRequest, request: Request) -> dict[str, bool]:
    get_manager(request).get(body.session_id).cancel()
    return {"ok": True}


@router.get("/api/status")
async def status(session_id: str, request: Request) -> dict[str, Any]:
    return get_manager(request).get(session_id).get_stats()


@router.get("/api/events/{session_id}")
async def events(session_id: str, request: Request) -> StreamingResponse:
    """Server-sent events: replays history, then streams ``result``/``stats`` until done."""
    session = get_manager(request).get(session_id)

    async def stream():
        index = 0
        while True:
            tick = session.next_tick()  # grab before reading so no event can be missed
            while index < len(session.events):
                yield f"data: {session.events[index]}\n\n"
                index += 1
            if session.finished or session.cancelled:
                final = json.dumps({"type": "done", **session.get_stats()})
                yield f"data: {final}\n\n"
                return
            try:
                await asyncio.wait_for(tick.wait(), timeout=15)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── Export / subscription ──────────────────────────────────────────────────

@router.get("/api/export/{session_id}/{fmt}")
async def export(session_id: str, fmt: str, request: Request) -> Response:
    session = get_manager(request).get(session_id)
    live = session.live_configs()

    if fmt == "txt":
        return Response(
            "\n".join(r.config for r in live),
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=live_configs.txt"},
        )
    if fmt == "json":
        data = [
            {
                "delay": r.delay,
                "protocol": r.protocol,
                "server": r.server,
                "port": r.port,
                "remark": r.remark,
                "config": r.config,
            }
            for r in live
        ]
        return Response(
            json.dumps(data, indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={
                "Content-Disposition": "attachment; filename=live_configs.json"},
        )
    if fmt == "clipboard":
        return JSONResponse({"configs": "\n".join(r.config for r in live), "count": len(live)})
    raise HTTPException(400, detail="Unknown export format")


@router.get("/sub/{session_id}")
async def subscription(session_id: str, request: Request) -> Response:
    """Live subscription: Base64 of the currently alive configs, fastest first."""
    session = get_manager(request).get(session_id)
    body = "\n".join(r.config for r in session.live_configs())
    return Response(
        base64.b64encode(body.encode("utf-8")),
        media_type="text/plain",
        headers={"Cache-Control": "no-store", "Profile-Update-Interval": "1"},
    )


# ─── Importing configs ──────────────────────────────────────────────────────

@router.post("/api/fetch-github")
async def fetch_github(body: FetchGithubRequest | None = None) -> dict[str, Any]:
    timeout = body.timeout if body else 20
    fetched = await fetch_sources(GITHUB_CONFIG_SOURCES, timeout=timeout)
    unique, dup_count = dedup_links(fetched.links)
    return {
        "configs": "\n".join(unique),
        "count": len(unique),
        "total_fetched": len(fetched.links),
        "duplicates": dup_count,
        "sources": fetched.source_counts,
        "errors": fetched.errors,
    }


@router.post("/api/fetch-url")
async def fetch_subscription(body: FetchUrlRequest) -> dict[str, Any]:
    url = body.url.strip()
    if not url:
        raise HTTPException(400, detail="URL is required")
    try:
        links = await fetch_url(url, body.timeout)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(502, detail=f"Failed to fetch: {exc}") from exc
    return {"configs": "\n".join(links), "count": len(links)}


# ─── QR codes ───────────────────────────────────────────────────────────────

@router.get("/api/qr")
async def qr_code(data: str) -> Response:
    """SVG QR code for a single proxy link (used by the dashboard's import modal)."""
    if len(data.encode("utf-8")) > MAX_QR_BYTES:
        raise HTTPException(413, detail="Config too long for a QR code")
    try:
        parse_link(data)  # only proxy links; this is not a generic QR service
    except ValueError as exc:
        raise HTTPException(400, detail="Not a supported proxy link") from exc

    import qrcode
    import qrcode.constants
    import qrcode.image.svg

    image = qrcode.make(
        data,
        image_factory=qrcode.image.svg.SvgFillImage,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=2,
    )
    buf = io.BytesIO()
    image.save(buf)
    return Response(buf.getvalue(), media_type="image/svg+xml", headers={"Cache-Control": "no-store"})
