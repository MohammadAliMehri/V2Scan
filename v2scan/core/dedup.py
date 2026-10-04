"""Deterministic config hashing and duplicate elimination."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import parse_qsl

from .parsers.base import ParseError, b64_decode, split_url


def _vmess_signature(link: str) -> str:
    body = link.partition("://")[2].partition("#")[0]
    if "@" in body:  # URL-style vmess
        return _url_signature(link)
    data = json.loads(b64_decode(body))
    if not isinstance(data, dict):
        raise ParseError("vmess payload is not an object")
    for key in ("ps", "class"):
        data.pop(key, None)
    return "vmess:" + json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _url_signature(link: str) -> str:
    """``scheme://user@host:port/path?query`` with the fragment dropped and query sorted."""
    url = split_url(link.partition("#")[0])
    scheme = "hysteria2" if url.scheme == "hy2" else url.scheme
    query = "&".join(f"{k}={v}" for k, v in sorted(parse_qsl(link.partition("#")[0].partition("?")[2],
                                                             keep_blank_values=True)))
    return f"{scheme}://{url.userinfo}@{url.host.lower()}:{url.port_text}{url.path}?{query}"


def config_signature(link: str) -> str:
    """Remark-independent canonical form of a link (falls back to the fragment-less link)."""
    link = link.strip()
    try:
        if link.lower().startswith("vmess://"):
            return _vmess_signature(link)
        if link.lower().startswith("ss://") and "@" not in link.partition("#")[0]:
            # legacy base64 form: no structure to normalise
            return link.partition("#")[0]
        return _url_signature(link)
    except Exception:
        return link.partition("#")[0]


def config_hash(link: str) -> str:
    """SHA-256 hex digest identifying a config regardless of its remark."""
    return hashlib.sha256(config_signature(link).encode("utf-8")).hexdigest()


def dedup_links(links: list[str]) -> tuple[list[str], int]:
    """Drop duplicates keeping discovery order. Returns ``(unique, removed_count)``."""
    seen: dict[str, str] = {}
    for link in links:
        seen.setdefault(config_hash(link), link)
    unique = list(seen.values())
    return unique, len(links) - len(unique)
