"""VLESS parser (TLS, REALITY, WS, gRPC, HTTPUpgrade, TCP)."""

from __future__ import annotations

from ..models import ProxyConfig
from .base import BaseParser, ParseError, build_tls, build_transport, parse_port, split_url


class VlessParser(BaseParser):
    protocol = "vless"
    schemes = ("vless",)

    def _parse(self, link: str) -> ProxyConfig:
        url = split_url(link)
        if not url.userinfo:
            raise ParseError("missing uuid")
        if not url.host:
            raise ParseError("missing host")
        q = url.query
        port = parse_port(url.port_text, default=443)

        security = (q.get("security") or "none").lower()
        net = (q.get("type") or "tcp").lower()
        sni = q.get("sni") or q.get("peer") or url.host

        outbound: dict = {
            "type": "vless",
            "tag": "out",
            "server": url.host,
            "server_port": port,
            "uuid": url.userinfo,
        }
        if q.get("flow"):
            outbound["flow"] = q["flow"]
        if q.get("packetEncoding"):
            outbound["packet_encoding"] = q["packetEncoding"]

        tls = build_tls(q, sni, security)
        if tls:
            outbound["tls"] = tls
        transport = build_transport(
            net,
            host=q.get("host") or sni,
            path=q.get("path", "/"),
            service_name=q.get("serviceName", ""),
            header_type=q.get("headerType", ""),
        )
        if transport:
            outbound["transport"] = transport

        extra = {k: q[k] for k in ("spx", "pbk", "sid", "fp") if q.get(k)}
        return ProxyConfig(
            link=link,
            protocol=self.protocol,
            address=url.host,
            port=port,
            remark=url.fragment,
            secret=url.userinfo,
            transport=net,
            security=security,
            outbound=outbound,
            extra=extra,
        )
