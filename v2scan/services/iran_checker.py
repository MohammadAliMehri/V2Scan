"""linkirani.ir host checker with token-bucket rate limiting, 429 back-off and GeoIP fallback."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from ..core.config import IRAN_API_URL, format_time, random_user_agent

# GeoIP providers tried in order when the linkirani API is unusable for a host.
_GEOIP_PROVIDERS: tuple[tuple[str, str], ...] = (
    ("https://api.country.is/{ip}", "country"),
    ("https://ipwho.is/{ip}", "country_code"),
)


def random_headers() -> dict[str, str]:
    """Browser-like headers for the linkirani API."""
    return {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://linkirani.ir",
        "Referer": "https://linkirani.ir/",
        "User-Agent": random_user_agent(),
        "DNT": "1",
    }


class TokenBucket:
    """Async token bucket; ``penalize`` pauses every consumer (used on HTTP 429)."""

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = max(0.1, rate)
        self.capacity = capacity if capacity is not None else max(
            1.0, self.rate)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._blocked_until = 0.0
        self._lock = asyncio.Lock()

    def penalize(self, seconds: float) -> None:
        self._blocked_until = max(
            self._blocked_until, time.monotonic() + seconds)

    async def acquire(self) -> None:
        async with self._lock:  # serialises waiters so the bucket can't be over-drawn
            while True:
                now = time.monotonic()
                if now < self._blocked_until:
                    await asyncio.sleep(self._blocked_until - now)
                    continue
                self._tokens = min(self.capacity, self._tokens +
                                   (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self.rate)


@dataclass
class IranStats:
    """Progress counters for a host check run."""

    total_hosts: int = 0
    done_hosts: int = 0
    total_configs: int = 0
    matched_configs: int = 0
    failed_configs: int = 0
    invalid_configs: int = 0
    api_errors: int = 0
    rate_limited: int = 0
    geoip_matches: int = 0
    start_time: float | None = None
    matched_hosts: list[str] = field(default_factory=list)

    @property
    def progress(self) -> float:
        return self.done_hosts / self.total_hosts * 100 if self.total_hosts else 0.0

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time if self.start_time else 0.0

    def elapsed(self) -> str:
        return format_time(self.elapsed_seconds) if self.start_time else "0s"

    def speed(self) -> str:
        if not self.start_time or not self.done_hosts:
            return "0/s"
        return f"{self.done_hosts / self.elapsed_seconds:.1f}/s"

    def eta(self) -> str:
        if not self.start_time or not self.done_hosts:
            return "calculating..."
        rate = self.done_hosts / self.elapsed_seconds
        return format_time((self.total_hosts - self.done_hosts) / rate)


@dataclass(slots=True)
class HostResult:
    host: str
    matched: bool
    source: str  # "api" | "geoip" | "none"


class IranChecker:
    """Check hosts concurrently against the linkirani API.

    A host matches when ``isRegistered`` and ``isInIran`` are true and ``ipCountryCode == "ir"``.
    """

    def __init__(
        self,
        *,
        concurrency: int = 100,
        retries: int = 3,
        rate: float = 50.0,
        geoip_fallback: bool = True,
        stats: IranStats | None = None,
        on_done: Callable[[HostResult], None] | None = None,
    ) -> None:
        self.concurrency = max(1, concurrency)
        self.retries = max(0, retries)
        self.stats = stats or IranStats()
        self.geoip_fallback = geoip_fallback
        self.on_done = on_done
        self._bucket = TokenBucket(rate)
        self._geo_bucket = TokenBucket(5.0)

    async def check_hosts(self, hosts: list[str]) -> dict[str, HostResult]:
        """Check every host; returns ``host -> HostResult`` (insertion order of ``hosts``)."""
        sem = asyncio.Semaphore(self.concurrency)
        results: dict[str, HostResult] = {}
        limits = httpx.Limits(
            max_connections=self.concurrency, max_keepalive_connections=20)
        async with httpx.AsyncClient(limits=limits, timeout=15.0, http2=True) as client:
            async def one(host: str) -> None:
                async with sem:
                    result = await self._check(client, host)
                results[host] = result
                self.stats.done_hosts += 1
                if self.on_done:
                    self.on_done(result)

            await asyncio.gather(*(one(h) for h in hosts))
        return {h: results[h] for h in hosts}

    # ── linkirani API ───────────────────────────────────────────────────────

    async def _check(self, client: httpx.AsyncClient, host: str) -> HostResult:
        verdict = await self._query_api(client, host)
        if verdict is not None:
            return HostResult(host, verdict, "api")
        self.stats.api_errors += 1
        if self.geoip_fallback and await self._geoip_is_iran(client, host):
            self.stats.geoip_matches += 1
            return HostResult(host, True, "geoip")
        return HostResult(host, False, "none")

    async def _query_api(self, client: httpx.AsyncClient, host: str) -> bool | None:
        """``True``/``False`` on a definite answer, ``None`` if every attempt failed."""
        for attempt in range(self.retries + 1):
            await self._bucket.acquire()
            try:
                resp = await client.post(
                    IRAN_API_URL, headers=random_headers(), json={"url": host}, timeout=10
                )
            except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError):
                await self._backoff(attempt)
                continue
            except httpx.HTTPError:
                return None

            if resp.status_code == 429:
                self.stats.rate_limited += 1
                delay = self._retry_after(resp) or (
                    2 ** attempt + random.uniform(0, 1))
                self._bucket.penalize(delay)
                continue
            if resp.status_code != 200:
                await asyncio.sleep(1)
                continue
            try:
                data = resp.json()
            except ValueError:
                return None
            return (
                data.get("isRegistered") is True
                and (data.get("ipCountryCode") or "").lower() == "ir"
                and data.get("isInIran") is True
            )
        return None

    @staticmethod
    def _retry_after(resp: httpx.Response) -> float:
        try:
            return min(60.0, float(resp.headers.get("Retry-After", "")))
        except ValueError:
            return 0.0

    @staticmethod
    async def _backoff(attempt: int) -> None:
        await asyncio.sleep(2 ** attempt + random.uniform(0, 1))

    # ── GeoIP fallback ──────────────────────────────────────────────────────

    async def _geoip_is_iran(self, client: httpx.AsyncClient, host: str) -> bool:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=0)
        except OSError:
            return False
        if not infos:
            return False
        ip = infos[0][4][0]
        for url_template, key in _GEOIP_PROVIDERS:
            await self._geo_bucket.acquire()
            try:
                resp = await client.get(url_template.format(ip=ip), timeout=8)
                if resp.status_code == 200:
                    return str(resp.json().get(key, "")).upper() == "IR"
            except (httpx.HTTPError, ValueError):
                continue
        return False
