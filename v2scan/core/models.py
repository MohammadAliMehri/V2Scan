"""Data models shared by the CLI, the tester and the web API."""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from .config import format_time


@dataclass(slots=True)
class ProxyConfig:
    """A parsed proxy link plus its sing-box outbound definition."""

    link: str
    protocol: str
    address: str
    port: int
    remark: str
    secret: str  # uuid / password
    transport: str
    security: str
    outbound: dict[str, Any]
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return the standardized metadata (no outbound / secrets)."""
        return {
            "protocol": self.protocol,
            "address": self.address,
            "port": self.port,
            "remark": self.remark,
            "transport": self.transport,
            "security": self.security,
        }


@dataclass
class TestResult:
    """Outcome of one latency probe."""

    __test__ = False  # not a pytest test class

    index: int
    link: str
    protocol: str
    server: str
    port: int
    remark: str
    status: str  # "alive" | "dead"
    delay: int = 0
    error: str = ""
    config: str = ""  # link re-tagged with the measured delay (alive only)

    @property
    def alive(self) -> bool:
        return self.status == "alive"

    def to_event(self) -> dict[str, Any]:
        """Payload sent to web clients (the raw link is never echoed for dead nodes)."""
        data: dict[str, Any] = {
            "index": self.index,
            "protocol": self.protocol,
            "server": self.server,
            "port": self.port,
            "remark": self.remark,
            "status": self.status,
            "delay": self.delay,
        }
        if self.error:
            data["error"] = self.error
        if self.alive:
            data["config"] = self.config
        return data


class ScanStats:
    """Mutable progress counters for a scan (used by the CLI dashboard and web sessions)."""

    SPEED_WINDOW = 30.0

    def __init__(self, total: int, parallel: int = 0) -> None:
        self.total = total
        self.parallel = parallel
        self.done = 0
        self.alive = 0
        self.dead = 0
        self.testing = 0
        self.delays: list[int] = []
        self.start_time: float | None = None
        self.recent: list[TestResult] = []
        self._samples: deque[tuple[float, int]] = deque()

    def start(self) -> None:
        self.start_time = time.time()
        self._samples.append((self.start_time, 0))

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time if self.start_time else 0.0

    @property
    def speed(self) -> float:
        """Configs/second over the last ~30s (instant failures at the start must not skew it)."""
        now = time.time()
        while len(self._samples) > 1 and self._samples[1][0] <= now - self.SPEED_WINDOW:
            self._samples.popleft()
        if not self._samples:
            return 0.0
        then, done_then = self._samples[0]
        span = now - then
        return (self.done - done_then) / span if span > 0 else 0.0

    @property
    def eta(self) -> float:
        speed = self.speed
        return (self.total - self.done) / speed if speed > 0 else 0.0

    @property
    def progress(self) -> float:
        return self.done / self.total * 100 if self.total else 0.0

    def mark_testing(self) -> None:
        self.testing += 1

    def record(self, result: TestResult, *, was_testing: bool = True) -> None:
        """Account for one finished config."""
        if was_testing and self.testing > 0:
            self.testing -= 1
        self.done += 1
        if self._samples:
            self._samples.append((time.time(), self.done))
        if result.alive:
            self.alive += 1
            if result.delay > 0:
                self.delays.append(result.delay)
        else:
            self.dead += 1
        self.recent.append(result)
        if len(self.recent) > 8:
            self.recent.pop(0)

    def eta_text(self) -> str:
        return format_time(self.eta) if self.done else "calculating..."

    def as_dict(self) -> dict[str, Any]:
        delays = self.delays
        return {
            "total": self.total,
            "done": self.done,
            "alive": self.alive,
            "dead": self.dead,
            "testing": self.testing,
            "elapsed": round(self.elapsed, 1),
            "speed": round(self.speed, 2),
            "eta": round(self.eta, 1),
            "progress": round(self.progress, 1),
            "min_delay": min(delays) if delays else 0,
            "avg_delay": round(sum(delays) / len(delays)) if delays else 0,
            "max_delay": max(delays) if delays else 0,
        }


class ScanSession:
    """A web scan: links, settings, results and a replayable event log for SSE clients."""

    def __init__(self, session_id: str, links: list[str], settings: dict[str, Any]) -> None:
        self.session_id = session_id
        self.links = links
        self.settings = settings
        self.stats = ScanStats(len(links), int(
            settings.get("parallel", 0) or 0))
        self.results: list[TestResult] = []
        self.events: list[str] = []
        self.running = False
        self.finished = False
        self.cancelled = False
        self.task: asyncio.Task[None] | None = None
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self._tick = asyncio.Event()

    def push_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Append an event and wake every SSE subscriber."""
        self.events.append(json.dumps(
            {"type": event_type, **data}, ensure_ascii=False))
        previous, self._tick = self._tick, asyncio.Event()
        previous.set()

    def next_tick(self) -> asyncio.Event:
        """Event that is set on the next ``push_event`` call."""
        return self._tick

    def cancel(self) -> None:
        """Flag the session cancelled and cancel its scan task (cleans up sing-box)."""
        self.cancelled = True
        if self.task and not self.task.done():
            self.task.cancel()
        previous, self._tick = self._tick, asyncio.Event()
        previous.set()

    def live_configs(self) -> list[TestResult]:
        """Alive results, fastest first."""
        return sorted((r for r in self.results if r.alive), key=lambda r: r.delay)

    def get_stats(self) -> dict[str, Any]:
        data = self.stats.as_dict()
        data.update(
            running=self.running,
            finished=self.finished,
            cancelled=self.cancelled,
            protocol_counts=dict(self.protocol_counts),
        )
        return data
