"""End-to-end tester check against a local Shadowsocks server run by sing-box itself."""

from __future__ import annotations

import asyncio
import http.server
import threading

import pytest

from v2scan.core.singbox import SingBoxProcess, allocate_ports, ensure_singbox
from v2scan.core.tester import LatencyTester

PASSWORD = "test-password"


class _Probe(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


def test_alive_and_dead_configs():
    info = asyncio.run(ensure_singbox())
    if info is None:
        pytest.skip("sing-box not available")

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Probe)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    probe_url = f"http://127.0.0.1:{httpd.server_address[1]}/"

    async def scenario():
        (ss_port,) = allocate_ports(1)
        server_cfg = {
            "log": {"level": "error"},
            "inbounds": [{
                "type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1",
                "listen_port": ss_port, "method": "aes-256-gcm", "password": PASSWORD,
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
        }
        links = [
            f"ss://aes-256-gcm:{PASSWORD}@127.0.0.1:{ss_port}#good",
            f"ss://aes-256-gcm:wrong@127.0.0.1:{ss_port}#badpw",
            "ss://bad-method:pw@127.0.0.1:9#badmethod",
            "vmess://garbage",
        ]
        async with SingBoxProcess(info.path, server_cfg, [ss_port]):
            tester = LatencyTester(info, probe=probe_url,
                                   timeout=5, parallel=4)
            return await tester.run(links)

    try:
        results = asyncio.run(scenario())
    finally:
        httpd.shutdown()

    by_remark = {r.remark or r.link: r for r in results}
    assert len(results) == 4
    good = by_remark["good"]
    assert good.alive and good.delay >= 0 and good.config.endswith("ms")
    assert not by_remark["badpw"].alive
    assert "rejected" in by_remark["badmethod"].error
    assert "Parse error" in by_remark["vmess://garbage"].error
    assert sorted(r.index for r in results) == [1, 2, 3, 4]
