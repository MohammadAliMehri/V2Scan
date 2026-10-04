"""Hysteria 2 parser (``hysteria2://`` / ``hy2://``): password, SNI, port hopping, obfs."""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from ..models import ProxyConfig
from .base import BaseParser, ParseError, build_tls, parse_port, split_url, truthy


def _parse_ports(text: str) -> tuple[int, list[str]]:
    """Parse ``443,5000-6000`` into ``(primary_port, ["5000:6000"])``."""
    singles: list[int] = []
    ranges: list[str] = []
    for part in filter(None, (p.strip() for p in text.replace(":", "-").split(","))):
        if "-" in part:
            start_text, _, end_text = part.partition("-")
            start, end = parse_port(start_text), parse_port(end_text)
            if start > end:
                raise ParseError(f"invalid port range: {part}")
            ranges.append(f"{start}:{end}")
        else:
            singles.append(parse_port(part))
    if not singles and not ranges:
        raise ParseError("missing port")
    primary = singles[0] if singles else int(ranges[0].split(":")[0])
    return primary, ranges


class Hysteria2Parser(BaseParser):
    protocol = "hysteria2"
    schemes = ("hysteria2", "hy2")

    def _parse(self, link: str) -> ProxyConfig:
        url = split_url(link)
        if not url.userinfo:
            raise ParseError("missing password")
        if not url.host:
            raise ParseError("missing host")
        q = url.query

        port_text = url.port_text or "443"
        if q.get("mport"):
            port_text = f"{port_text},{q['mport']}"
        port, ranges = _parse_ports(port_text)

        outbound: dict[str, Any] = {
            "type": "hysteria2",
            "tag": "out",
            "server": url.host,
            "server_port": port,
            "password": url.userinfo,
        }
        if ranges:
            outbound["server_ports"] = ranges

        sni = q.get("sni") or q.get("peer") or url.host
        tls = build_tls(q, sni, "tls", insecure=truthy(q.get("insecure")))
        assert tls is not None
        outbound["tls"] = tls

        obfs_kind = q.get("obfs", "").strip()
        if obfs_kind.lower() not in ("", "none"):
            # sing-box only implements salamander; any other value is taken as the password.
            password = q.get("obfs-password") or (
                "" if obfs_kind.lower() == "salamander" else unquote(obfs_kind)
            )
            if not password:
                raise ParseError("obfs=salamander requires obfs-password")
            outbound["obfs"] = {"type": "salamander", "password": password}

        return ProxyConfig(
            link=link,
            protocol=self.protocol,
            address=url.host,
            port=port,
            remark=url.fragment,
            secret=url.userinfo,
            transport="quic",
            security="tls",
            outbound=outbound,
            extra={k: q[k] for k in ("pinSHA256", "mport") if q.get(k)},
        )
