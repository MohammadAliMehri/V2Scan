"""Shared parsing helpers and the abstract base parser."""

from __future__ import annotations

import base64
import binascii
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, unquote

from ..models import ProxyConfig


class ParseError(ValueError):
    """Raised when a link is malformed or uses something sing-box cannot express."""


# ─── Low-level helpers ──────────────────────────────────────────────────────

def b64_decode(data: str) -> str:
    """Decode standard or URL-safe base64 (padding optional) to text."""
    data = "".join(data.split())
    data += "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError) as exc:
        raise ParseError(f"invalid base64: {exc}") from exc


def b64_encode(text: str) -> str:
    """Standard base64 with padding."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def parse_port(value: Any, default: int | None = None) -> int:
    """Validate a TCP/UDP port number."""
    if value in (None, ""):
        if default is None:
            raise ParseError("missing port")
        return default
    try:
        port = int(str(value).strip())
    except ValueError as exc:
        raise ParseError(f"invalid port: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ParseError(f"port out of range: {port}")
    return port


def split_hostport(hostport: str) -> tuple[str, str]:
    """Split ``host:port`` / ``[v6]:port`` / ``host`` into ``(host, port_text)``."""
    hostport = hostport.strip()
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            raise ParseError("unterminated IPv6 literal")
        return hostport[1:end], hostport[end + 1:].lstrip(":")
    host, sep, port = hostport.rpartition(":")
    if not sep:
        return hostport, ""
    return host, port


def truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def first_non_empty(*values: Any) -> Any:
    """Return the first value that is not ``None`` / empty string."""
    for value in values:
        if value not in (None, ""):
            return value
    return ""


@dataclass(slots=True)
class UrlParts:
    """Components of a ``scheme://userinfo@host:port/path?query#fragment`` link."""

    scheme: str
    userinfo: str
    host: str
    port_text: str
    path: str
    query: dict[str, str]
    fragment: str


def split_url(link: str) -> UrlParts:
    """Tolerant URL splitter (does not choke on odd ports or unencoded fragments)."""
    scheme, sep, rest = link.strip().partition("://")
    if not sep or not scheme:
        raise ParseError("not a URL")
    rest, _, fragment = rest.partition("#")
    rest, _, query_text = rest.partition("?")
    authority, slash, path = rest.partition("/")
    userinfo, _, hostport = authority.rpartition("@")
    host, port_text = split_hostport(hostport)
    query = {k: v[0] for k, v in parse_qs(
        query_text, keep_blank_values=True).items()}
    return UrlParts(
        scheme=scheme.lower(),
        userinfo=unquote(userinfo),
        host=host,
        port_text=port_text,
        path=slash + path,
        query=query,
        fragment=unquote(fragment),
    )


# ─── sing-box fragment builders ─────────────────────────────────────────────

def build_tls(
    query: dict[str, str],
    server_name: str,
    security: str,
    *,
    insecure: bool = False,
    alpn: str = "",
    fingerprint: str = "",
) -> dict[str, Any] | None:
    """Build the sing-box ``tls`` block for ``tls`` / ``reality`` security (else ``None``)."""
    if security not in ("tls", "reality", "xtls"):
        return None
    tls: dict[str, Any] = {"enabled": True, "server_name": server_name}
    if insecure or truthy(query.get("allowInsecure")) or truthy(query.get("insecure")):
        tls["insecure"] = True
    alpn = alpn or query.get("alpn", "")
    if alpn:
        tls["alpn"] = [a for a in alpn.split(",") if a]
    fp = fingerprint or query.get("fp", "")
    if security == "reality":
        public_key = query.get("pbk", "")
        if not public_key:
            raise ParseError("REALITY requires pbk")
        tls["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": query.get("sid", ""),
        }
        tls["utls"] = {"enabled": True, "fingerprint": fp or "chrome"}
    elif fp and fp != "none":
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    return tls


def build_transport(
    kind: str,
    *,
    host: str,
    path: str,
    service_name: str = "",
    header_type: str = "",
) -> dict[str, Any] | None:
    """Build the sing-box ``transport`` block for a V2Ray-style network type."""
    kind = (kind or "tcp").lower()
    if kind == "raw":  # Xray's name for plain TCP
        kind = "tcp"
    if kind == "tcp":
        if header_type == "http":
            return {"type": "http", "host": [h for h in host.split(",") if h], "path": path or "/"}
        return None
    if kind == "ws":
        transport: dict[str, Any] = {"type": "ws", "path": path or "/"}
        if "?" in transport["path"]:
            base, _, extra = transport["path"].partition("?")
            params = parse_qs(extra)
            early = params.get("ed", [""])[0]
            if early.isdigit():
                transport["path"] = base or "/"
                transport["max_early_data"] = int(early)
                transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if kind == "grpc":
        return {"type": "grpc", "service_name": service_name}
    if kind == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path or "/"}
        if host:
            transport["host"] = host
        return transport
    if kind in ("h2", "http"):
        return {"type": "http", "host": [h for h in host.split(",") if h], "path": path or "/"}
    raise ParseError(f"unsupported transport: {kind}")


# ─── Parser interface ───────────────────────────────────────────────────────

class BaseParser(ABC):
    """One parser per protocol: link -> :class:`ProxyConfig`, and remark rewriting."""

    protocol: str
    schemes: tuple[str, ...]

    def matches(self, link: str) -> bool:
        return link.lower().startswith(tuple(f"{s}://" for s in self.schemes))

    def parse(self, link: str) -> ProxyConfig:
        """Parse ``link``; any failure is normalised to :class:`ParseError`."""
        link = link.strip()
        try:
            return self._parse(link)
        except ParseError:
            raise
        except Exception as exc:  # malformed input must never crash a batch
            raise ParseError(f"{self.protocol}: {exc}") from exc

    @abstractmethod
    def _parse(self, link: str) -> ProxyConfig:
        """Protocol-specific parsing."""

    def with_remark(self, link: str, remark: str) -> str:
        """Return ``link`` with its display name replaced (fragment based by default)."""
        return link.strip().partition("#")[0] + "#" + remark
