"""Async latency tester: batches many configs into one sing-box process each."""

from __future__ import annotations

import asyncio
import math
import re
import time
from collections.abc import Callable

import httpx

from .config import DEFAULT_BATCH_SIZE, MAX_WORKERS
from .models import ProxyConfig, TestResult
from .parsers import ParseError, get_protocol, parse_link, set_remark
from .singbox import (
    SingBoxError,
    SingBoxInfo,
    SingBoxProcess,
    allocate_ports,
    build_batch_config,
    find_failed_outbound,
)

StartCallback = Callable[[], None]
ResultCallback = Callable[[TestResult], None]

_PORT_CONFLICT_MARKERS = ("address already in use", "only one usage", "bind:")
_MAX_PORT_RETRIES = 2


def _last_line(text: str, limit: int = 160) -> str:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    line = re.sub(r"^\w+\[\d+\]\s*(create service:\s*)?",
                  "", lines[-1]) if lines else "no output"
    return line[:limit]


class LatencyTester:
    """Tests links through local SOCKS inbounds of shared sing-box processes.

    Configs are grouped into batches; each batch runs in a single sing-box process whose
    config has one SOCKS inbound per outbound. ``parallel`` bounds concurrent probes overall.
    A batch sing-box refuses to start is split until the offending config is isolated.
    Cancel by cancelling the task awaiting :meth:`run`; processes and temp dirs are cleaned up.
    """

    def __init__(
        self,
        singbox: SingBoxInfo,
        *,
        probe: str,
        timeout: int = 15,
        startup_wait: float = 2.0,
        parallel: int = 3,
        batch_size: int = DEFAULT_BATCH_SIZE,
        on_start: StartCallback | None = None,
        on_result: ResultCallback | None = None,
    ) -> None:
        self.singbox = singbox
        self.probe = probe
        self.timeout = max(1, int(timeout))
        self.startup_wait = startup_wait
        self.parallel = max(1, int(parallel))
        self.batch_size = max(1, int(batch_size))
        self.on_start = on_start
        self.on_result = on_result
        self.results: list[TestResult] = []
        self._sem = asyncio.Semaphore(self.parallel)
        self._ssl = httpx.create_ssl_context()

    # ── public API ──────────────────────────────────────────────────────────

    async def run(self, links: list[str]) -> list[TestResult]:
        """Test every link; returns results in completion order."""
        valid: list[tuple[str, ProxyConfig]] = []
        for link in links:
            try:
                valid.append((link, parse_link(link)))
            except ParseError as exc:
                self._emit_dead(link, None, f"Parse error: {exc}")
        if not valid:
            return self.results

        workers = max(1, min(MAX_WORKERS, math.ceil(
            self.parallel / 10), len(valid)))
        size = max(1, min(self.batch_size, math.ceil(len(valid) / workers)))
        queue: asyncio.Queue[list[tuple[str, ProxyConfig]]] = asyncio.Queue()
        for i in range(0, len(valid), size):
            queue.put_nowait(valid[i:i + size])

        async def worker() -> None:
            while True:
                try:
                    batch = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                await self._run_batch(batch)

        await asyncio.gather(*(worker() for _ in range(min(workers, queue.qsize()))))
        return self.results

    # ── batch execution ─────────────────────────────────────────────────────

    async def _run_batch(self, batch: list[tuple[str, ProxyConfig]], attempt: int = 0) -> None:
        if not batch:
            return
        ports = allocate_ports(len(batch))
        config = build_batch_config(
            [cfg.outbound for _, cfg in batch], ports, modern=self.singbox.modern
        )
        proc = SingBoxProcess(self.singbox.path, config, ports)
        try:
            await proc.start(ready_timeout=max(10.0, self.startup_wait))
        except SingBoxError as exc:
            await self._handle_start_failure(batch, exc.log or str(exc), attempt)
            return
        try:
            await asyncio.gather(
                *(self._probe_one(link, cfg, port) for (link, cfg), port in zip(batch, ports))
            )
        finally:
            await proc.stop()

    async def _handle_start_failure(
        self, batch: list[tuple[str, ProxyConfig]], log: str, attempt: int
    ) -> None:
        lowered = log.lower()
        if attempt < _MAX_PORT_RETRIES and any(m in lowered for m in _PORT_CONFLICT_MARKERS):
            await self._run_batch(batch, attempt + 1)
            return
        if len(batch) == 1:
            link, cfg = batch[0]
            self._emit_dead(
                link, cfg, f"sing-box rejected config: {_last_line(log)}")
            return
        bad = find_failed_outbound(log, len(batch))
        if bad is not None:
            link, cfg = batch[bad]
            self._emit_dead(
                link, cfg, f"sing-box rejected config: {_last_line(log)}")
            await self._run_batch(batch[:bad] + batch[bad + 1:])
            return
        mid = len(batch) // 2
        await self._run_batch(batch[:mid])
        await self._run_batch(batch[mid:])

    # ── probing ─────────────────────────────────────────────────────────────

    async def _probe_one(self, link: str, cfg: ProxyConfig, port: int) -> None:
        async with self._sem:
            if self.on_start:
                self.on_start()
            alive, delay, error = await self._http_probe(port)
        if alive:
            self._emit(TestResult(
                index=0, link=link, protocol=cfg.protocol, server=cfg.address, port=cfg.port,
                remark=cfg.remark, status="alive", delay=delay,
                config=set_remark(link, f"🚀{delay}ms"),
            ))
        else:
            self._emit(self._dead(link, cfg, error))

    async def _http_probe(self, port: int) -> tuple[bool, int, str]:
        """GET the probe URL through the SOCKS inbound; returns ``(alive, delay_ms, error)``."""
        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                proxy=f"socks5://127.0.0.1:{port}",
                timeout=self.timeout,
                follow_redirects=True,
                verify=self._ssl,
                headers={"User-Agent": "Mozilla/5.0 V2Scan/2.0"},
            ) as client:
                resp = await asyncio.wait_for(client.get(self.probe), timeout=self.timeout)
        except (asyncio.TimeoutError, httpx.TimeoutException):
            return False, 0, "Timeout"
        except httpx.ProxyError:
            # SOCKS failure: sing-box could not reach the node
            return False, 0, "Server unreachable"
        except (httpx.HTTPError, OSError) as exc:
            return False, 0, f"Connection failed ({type(exc).__name__})"
        delay = int((time.perf_counter() - started) * 1000)
        if 200 <= resp.status_code < 400:
            return True, delay, ""
        return False, 0, f"HTTP {resp.status_code}"

    # ── result plumbing ─────────────────────────────────────────────────────

    def _dead(self, link: str, cfg: ProxyConfig | None, error: str) -> TestResult:
        return TestResult(
            index=0,
            link=link,
            protocol=cfg.protocol if cfg else get_protocol(link),
            server=cfg.address if cfg else "",
            port=cfg.port if cfg else 0,
            remark=cfg.remark if cfg else "",
            status="dead",
            error=error,
        )

    def _emit_dead(self, link: str, cfg: ProxyConfig | None, error: str) -> None:
        """Dead result for a config that never reached the probe stage."""
        if self.on_start:
            self.on_start()
        self._emit(self._dead(link, cfg, error))

    def _emit(self, result: TestResult) -> None:
        result.index = len(self.results) + 1
        self.results.append(result)
        if self.on_result:
            self.on_result(result)
