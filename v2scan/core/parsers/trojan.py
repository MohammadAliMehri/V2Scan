"""Trojan parser (TLS/REALITY, WS, gRPC, HTTPUpgrade, TCP)."""

from __future__ import annotations

from ..models import ProxyConfig
from .base import BaseParser, ParseError, build_tls, build_transport, parse_port, split_url


class TrojanParser(BaseParser):
    protocol = "trojan"
    schemes = ("trojan",)

    def _parse(self, link: str) -> ProxyConfig:
        url = split_url(link)
        if not url.userinfo:
            raise ParseError("missing password")
        if not url.host:
            raise ParseError("missing host")
        q = url.query
        port = parse_port(url.port_text, default=443)

        # Trojan is TLS by default; honour an explicit security=none/reality.
        security = (q.get("security") or "tls").lower()
        net = (q.get("type") or "tcp").lower()
        sni = q.get("sni") or q.get("peer") or url.host

        outbound: dict = {
            "type": "trojan",
            "tag": "out",
            "server": url.host,
            "server_port": port,
            "password": url.userinfo,
        }
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
        )
