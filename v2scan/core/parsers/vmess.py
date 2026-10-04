"""VMess parser (Base64 JSON links, plus the URL-style ``vmess://uuid@host:port`` form)."""

from __future__ import annotations

import json
from typing import Any

from ..models import ProxyConfig
from .base import (
    BaseParser,
    ParseError,
    b64_decode,
    b64_encode,
    build_tls,
    build_transport,
    first_non_empty,
    parse_port,
    split_url,
    truthy,
)

_NET_ALIASES = {"": "tcp", "none": "tcp",
                "websocket": "ws", "h2": "h2", "http": "h2"}


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


class VmessParser(BaseParser):
    protocol = "vmess"
    schemes = ("vmess",)

    def _parse(self, link: str) -> ProxyConfig:
        body = link.partition("://")[2].partition("#")[0]
        if "@" in body:
            return self._parse_url_style(link)

        raw = b64_decode(body).strip()
        if not raw.startswith("{"):
            raise ParseError("vmess payload is not JSON")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ParseError(f"invalid vmess JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ParseError("vmess JSON is not an object")

        address = str(first_non_empty(
            data.get("add"), data.get("host"))).strip()
        uuid = str(data.get("id") or "").strip()
        if not address:
            raise ParseError("missing address")
        if not uuid:
            raise ParseError("missing uuid")
        port = parse_port(data.get("port"), default=443)

        raw_net = str(data.get("net") or "").lower()
        net = _NET_ALIASES.get(raw_net, raw_net)
        host = str(data.get("host") or "").strip()
        path = str(data.get("path") or "")
        tls_flag = str(data.get("tls") or "").lower()
        security = "tls" if tls_flag in ("tls", "1", "true") else "none"
        sni = str(first_non_empty(data.get("sni"),
                  host.split(",")[0], address))

        outbound: dict[str, Any] = {
            "type": "vmess",
            "tag": "out",
            "server": address,
            "server_port": port,
            "uuid": uuid,
            "security": str(data.get("scy") or "auto"),
            "alter_id": _to_int(data.get("aid")),
        }
        tls = build_tls(
            {"allowInsecure": "1" if truthy(
                str(data.get("allowInsecure", ""))) else ""},
            sni,
            security,
            alpn=str(data.get("alpn") or ""),
            fingerprint=str(data.get("fp") or ""),
        )
        if tls:
            outbound["tls"] = tls
        transport = build_transport(
            net,
            host=host or address if net in (
                "ws", "httpupgrade", "h2") else host,
            path=path or "/",
            service_name=path,
            header_type=str(data.get("type") or ""),
        )
        if transport:
            outbound["transport"] = transport

        return ProxyConfig(
            link=link,
            protocol=self.protocol,
            address=address,
            port=port,
            remark=str(data.get("ps") or ""),
            secret=uuid,
            transport=net,
            security=security,
            outbound=outbound,
        )

    def _parse_url_style(self, link: str) -> ProxyConfig:
        """``vmess://uuid@host:port?type=ws&security=tls&...#remark`` (Xray share format)."""
        url = split_url(link)
        if not url.userinfo or not url.host:
            raise ParseError("missing uuid or host")
        q = url.query
        port = parse_port(url.port_text, default=443)
        security = (q.get("security") or "none").lower()
        net = _NET_ALIASES.get(
            (q.get("type") or "tcp").lower(), (q.get("type") or "tcp").lower())
        sni = q.get("sni") or url.host
        outbound: dict[str, Any] = {
            "type": "vmess",
            "tag": "out",
            "server": url.host,
            "server_port": port,
            "uuid": url.userinfo,
            "security": q.get("encryption") or "auto",
            "alter_id": 0,
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

    def with_remark(self, link: str, remark: str) -> str:
        link = link.strip()
        body = link.partition("://")[2].partition("#")[0]
        if "@" in body:  # URL-style: plain fragment rewrite
            return super().with_remark(link, remark)
        try:
            data = json.loads(b64_decode(body))
            data["ps"] = remark
        except (ParseError, json.JSONDecodeError, TypeError):
            return link
        return "vmess://" + b64_encode(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
