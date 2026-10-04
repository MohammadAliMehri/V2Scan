"""Parser and dedup tests."""

from __future__ import annotations

import base64
import json

import pytest

from v2scan.core.dedup import config_hash, dedup_links
from v2scan.core.parsers import ParseError, get_protocol, parse_link, set_remark


def vmess_link(**overrides) -> str:
    data = {"v": "2", "ps": "name", "add": "example.com", "port": "443", "id": "11111111-2222-3333-4444-555555555555",
            "aid": "0", "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/ws", "tls": "tls"}
    data.update(overrides)
    return "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()


def test_vless_reality():
    cfg = parse_link(
        "vless://uuid-1@1.2.3.4:443?security=reality&sni=www.apple.com&pbk=PUB&sid=ab&fp=firefox"
        "&spx=%2F&type=tcp&flow=xtls-rprx-vision#my%20node"
    )
    ob = cfg.outbound
    assert (cfg.protocol, cfg.address, cfg.port, cfg.remark) == (
        "vless", "1.2.3.4", 443, "my node")
    assert ob["flow"] == "xtls-rprx-vision"
    assert ob["tls"]["reality"] == {
        "enabled": True, "public_key": "PUB", "short_id": "ab"}
    assert ob["tls"]["utls"]["fingerprint"] == "firefox"
    assert cfg.extra["spx"] == "/"


def test_vless_ws_grpc_httpupgrade():
    ws = parse_link(
        "vless://u@h.com:443?security=tls&type=ws&path=%2Fa%3Fed%3D2048&host=x.com")
    assert ws.outbound["transport"] == {
        "type": "ws", "path": "/a", "max_early_data": 2048,
        "early_data_header_name": "Sec-WebSocket-Protocol", "headers": {"Host": "x.com"},
    }
    grpc = parse_link(
        "vless://u@h.com:443?security=tls&type=grpc&serviceName=svc")
    assert grpc.outbound["transport"] == {
        "type": "grpc", "service_name": "svc"}
    hu = parse_link("vless://u@h.com:80?type=httpupgrade&path=/p&host=x.com")
    assert hu.outbound["transport"]["type"] == "httpupgrade"
    assert "tls" not in hu.outbound


def test_vless_ipv6_and_unsupported_transport():
    assert parse_link(
        "vless://u@[2001:db8::1]:8443?type=tcp").address == "2001:db8::1"
    with pytest.raises(ParseError):
        parse_link("vless://u@h.com:443?type=xhttp")


def test_vmess_nonstandard_fields():
    cfg = parse_link(vmess_link(port=8443, aid="", scy="",
                     extra_field=[1, 2], net="websocket"))
    assert cfg.port == 8443
    assert cfg.outbound["alter_id"] == 0
    assert cfg.outbound["security"] == "auto"
    assert cfg.transport == "ws"
    assert cfg.outbound["transport"]["headers"] == {"Host": "cdn.example.com"}


def test_vmess_garbage_raises_parse_error():
    for bad in ("vmess://!!!notbase64", "vmess://" + base64.b64encode(b"not json").decode(), "vmess://"):
        with pytest.raises(ParseError):
            parse_link(bad)


def test_trojan():
    cfg = parse_link(
        "trojan://p%40ss:word@h.com:443?sni=s.com&type=grpc&serviceName=g#t")
    assert cfg.secret == "p@ss:word"
    assert cfg.outbound["tls"]["server_name"] == "s.com"
    assert cfg.outbound["transport"]["service_name"] == "g"


def test_shadowsocks_forms():
    userinfo = base64.urlsafe_b64encode(
        b"aes-256-gcm:pa:ss").decode().rstrip("=")
    sip002 = parse_link(
        f"ss://{userinfo}@1.1.1.1:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Da.com#n")
    assert sip002.outbound["method"] == "aes-256-gcm"
    assert sip002.outbound["password"] == "pa:ss"
    assert sip002.outbound["plugin"] == "obfs-local"
    assert sip002.outbound["plugin_opts"] == "obfs=http;obfs-host=a.com"

    legacy_raw = base64.b64encode(
        b"chacha20-ietf-poly1305:pw@2.2.2.2:443").decode()
    legacy = parse_link(f"ss://{legacy_raw}#old")
    assert (legacy.address, legacy.port, legacy.remark) == (
        "2.2.2.2", 443, "old")

    plain = parse_link("ss://2022-blake3-aes-128-gcm:key@3.3.3.3:1000")
    assert plain.outbound["method"] == "2022-blake3-aes-128-gcm"

    with pytest.raises(ParseError):
        parse_link(f"ss://{userinfo}@1.1.1.1:8388/?plugin=weird-plugin")


def test_hysteria2():
    cfg = parse_link(
        "hy2://secret@h.com:443,20000-30000?sni=s.com&insecure=1&obfs=salamander&obfs-password=ob#x")
    ob = cfg.outbound
    assert cfg.protocol == "hysteria2" and get_protocol(
        "hysteria2://a@b:1") == "hysteria2"
    assert ob["server_port"] == 443 and ob["server_ports"] == ["20000:30000"]
    assert ob["tls"]["insecure"] is True and ob["tls"]["server_name"] == "s.com"
    assert ob["obfs"] == {"type": "salamander", "password": "ob"}
    with pytest.raises(ParseError):
        parse_link("hy2://secret@h.com:443?obfs=salamander")


@pytest.mark.parametrize("bad", [
    "vless://", "vless://@:", "vless://u@h.com:99999", "trojan://@h.com", "ss://", "hy2://@h:1", "http://x", "",
])
def test_malformed_never_crashes(bad):
    with pytest.raises(ParseError):
        parse_link(bad)


def test_set_remark_roundtrip():
    assert set_remark("vless://u@h.com:443?type=ws#old",
                      "🚀5ms").endswith("#🚀5ms")
    renamed = set_remark(vmess_link(), "🚀9ms")
    assert parse_link(renamed).remark == "🚀9ms"


def test_dedup_ignores_remark_and_query_order():
    a = "vless://u@h.com:443?type=ws&security=tls#one"
    b = "vless://u@H.com:443?security=tls&type=ws#two"
    assert config_hash(a) == config_hash(b)
    assert config_hash("hy2://p@h:1") == config_hash("hysteria2://p@h:1#z")
    v1, v2 = vmess_link(ps="a"), vmess_link(ps="b")
    assert config_hash(v1) == config_hash(v2)
    assert config_hash(vmess_link(port="444")) != config_hash(v1)


def test_dedup_preserves_order():
    links = ["trojan://a@h:1#x", "vless://u@h:1#y",
             "trojan://a@h:1#z", "broken"]
    unique, removed = dedup_links(links)
    assert unique == ["trojan://a@h:1#x", "vless://u@h:1#y", "broken"]
    assert removed == 1
