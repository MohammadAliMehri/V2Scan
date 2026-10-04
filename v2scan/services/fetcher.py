"""Async collector for GitHub-hosted and custom subscription sources."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from ..core.config import ALL_PREFIXES, GITHUB_CONFIG_SOURCES
from ..core.parsers.base import ParseError, b64_decode

_USER_AGENT = "V2Scan/2.0"


@dataclass
class FetchResult:
    """Links gathered from several sources."""

    links: list[str] = field(default_factory=list)
    source_counts: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def extract_links(raw: str) -> list[str]:
    """Pull proxy links out of plain-text or base64 subscription content."""
    head = raw[:5000].lower()
    if not any(prefix in head for prefix in ALL_PREFIXES):
        try:
            decoded = b64_decode(raw)
        except ParseError:
            decoded = ""
        if any(prefix in decoded.lower() for prefix in ALL_PREFIXES):
            raw = decoded
    return [
        line.strip() for line in raw.splitlines()
        if line.strip().lower().startswith(ALL_PREFIXES)
    ]


async def fetch_url(url: str, timeout: float = 15, client: httpx.AsyncClient | None = None) -> list[str]:
    """Download one subscription URL (http/https only) and return its proxy links."""
    if urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https://")
    owns_client = client is None
    client = client or httpx.AsyncClient(
        timeout=timeout, follow_redirects=True)
    try:
        resp = await client.get(url, headers={"User-Agent": _USER_AGENT})
        resp.raise_for_status()
        return extract_links(resp.text)
    finally:
        if owns_client:
            await client.aclose()


async def fetch_sources(
    sources: list[tuple[str, str]] | None = None, timeout: float = 20
) -> FetchResult:
    """Fetch ``(url, description)`` sources concurrently (defaults to the built-in GitHub list)."""
    sources = sources if sources is not None else GITHUB_CONFIG_SOURCES
    result = FetchResult()

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=10),
    ) as client:
        async def one(url: str, desc: str) -> None:
            try:
                links = await fetch_url(url, timeout, client)
            except httpx.HTTPStatusError as exc:
                result.errors.append(
                    f"{desc}: HTTP {exc.response.status_code}")
                return
            except (httpx.HTTPError, ValueError, asyncio.TimeoutError) as exc:
                result.errors.append(
                    f"{desc}: {str(exc) or type(exc).__name__}")
                return
            result.links.extend(links)
            result.source_counts[desc] = len(links)

        await asyncio.gather(*(one(url, desc) for url, desc in sources))
    return result
