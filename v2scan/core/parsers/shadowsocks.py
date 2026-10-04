"""Shadowsocks parser (SIP002, legacy base64, AEAD / 2022 ciphers, obfs & v2ray plugins)."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, unquote

from ..models import ProxyConfig
from .base import BaseParser, ParseError, b64_decode, parse_port, split_hostport

# SIP003 plugin names -> sing-box plugin names
_PLUGINS = {"obfs-local": "obfs-local",
            "simple-obfs": "obfs-local", "v2ray-plugin": "v2ray-plugin"}


class ShadowsocksParser(BaseParser):
    protocol = "ss"
    schemes = ("ss",)

    def _parse(self, link: str) -> ProxyConfig:
        body, _, fragment = link.partition("://")[2].partition("#")
        body, _, query_text = body.partition("?")
        body = body.rstrip("/")

        if "@" in body:  # SIP002: [userinfo@]host:port
            userinfo, _, hostport = body.rpartition("@")
            userinfo = unquote(userinfo)
            if ":" not in userinfo:
                userinfo = b64_decode(userinfo)
        else:  # legacy: base64(method:password@host:port)
            decoded = b64_decode(unquote(body))
            if "@" not in decoded:
                raise ParseError("cannot locate server in ss link")
            userinfo, _, hostport = decoded.rpartition("@")

        method, sep, password = userinfo.partition(":")
        if not sep or not method:
            raise ParseError("missing method/password")
        host, port_text = split_hostport(hostport.split("/")[0])
        if not host:
            raise ParseError("missing host")
        port = parse_port(port_text)

        outbound: dict[str, Any] = {
            "type": "shadowsocks",
            "tag": "out",
            "server": host,
            "server_port": port,
            "method": method,
            "password": password,
        }

        plugin_raw = parse_qs(query_text).get("plugin", [""])[0]
        transport = "tcp"
        if plugin_raw:
            name, _, opts = plugin_raw.partition(";")
            if name not in _PLUGINS:
                raise ParseError(f"unsupported ss plugin: {name}")
            outbound["plugin"] = _PLUGINS[name]
            if opts:
                outbound["plugin_opts"] = opts
            transport = _PLUGINS[name]

        return ProxyConfig(
            link=link,
            protocol=self.protocol,
            address=host,
            port=port,
            remark=unquote(fragment),
            secret=password,
            transport=transport,
            security="none",
            outbound=outbound,
            extra={"method": method},
        )
