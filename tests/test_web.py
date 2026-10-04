"""Web API tests (no network; dead configs exercise the real sing-box batch path)."""

from __future__ import annotations

import asyncio
import base64
import json

import pytest
from fastapi.testclient import TestClient

from v2scan.core.singbox import ensure_singbox
from v2scan.web.server import create_app


@pytest.fixture()
def client():
    with TestClient(create_app()) as c:
        yield c


def read_events(client: TestClient, sid: str) -> list[dict]:
    events = []
    with client.stream("GET", f"/api/events/{sid}") as resp:
        assert resp.headers["content-type"].startswith("text/event-stream")
        for line in resp.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
                if events[-1]["type"] == "done":
                    break
    return events


def test_static_pages_and_validation(client):
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    assert client.post(
        "/api/start", json={"configs": "nothing here"}).status_code == 400
    bad = client.post(
        "/api/start", json={"configs": "ss://a:b@h:1", "settings": {"parallel": 0}})
    assert bad.status_code == 400 and "error" in bad.json()
    exe = client.post(
        "/api/start", json={"configs": "ss://a:b@h:1", "settings": {"singbox_path": "cmd.exe"}})
    assert exe.status_code == 400
    assert client.get(
        "/api/status", params={"session_id": "nope"}).status_code == 404
    # DNS-rebinding guard
    assert client.get("/", headers={"host": "evil.example"}).status_code == 400
    assert client.post(
        "/api/fetch-url", json={"url": "file:///etc/passwd"}).status_code == 400


def test_qr_endpoint(client):
    ok = client.get("/api/qr", params={"data": "trojan://pw@h.com:443#x"})
    assert ok.status_code == 200 and ok.headers["content-type"] == "image/svg+xml"
    assert client.get("/api/qr", params={"data": "hello"}).status_code == 400


def test_scan_session_flow(client):
    if asyncio.run(ensure_singbox()) is None:
        pytest.skip("sing-box not available")
    configs = "trojan://pw@127.0.0.1:9?sni=a.com#a\nvmess://garbage\nss://bad-method:pw@127.0.0.1:9#m"
    resp = client.post(
        "/api/start", json={"configs": configs, "settings": {"timeout": 3}})
    assert resp.status_code == 200, resp.text
    sid = resp.json()["session_id"]
    # vmess://garbage still matches the prefix
    assert resp.json()["total"] == 3 or resp.json()["total"] == 2

    events = read_events(client, sid)
    results = [e for e in events if e["type"] == "result"]
    assert len(results) == resp.json()["total"]
    assert all(r["status"] == "dead" for r in results)
    assert events[-1]["type"] == "done" and events[-1]["done"] == resp.json()["total"]

    assert base64.b64decode(client.get(f"/sub/{sid}").content) == b""
    assert client.get(f"/api/export/{sid}/json").json() == []
    assert client.get(
        f"/api/export/{sid}/clipboard").json() == {"configs": "", "count": 0}
    assert client.get(f"/api/export/{sid}/xml").status_code == 400
    assert client.post(
        "/api/cancel", json={"session_id": sid}).json() == {"ok": True}


def test_cancel_running_session(client):
    if asyncio.run(ensure_singbox()) is None:
        pytest.skip("sing-box not available")
    # Unroutable target + long timeout keeps the probe pending until we cancel.
    resp = client.post(
        "/api/start",
        json={"configs": "trojan://pw@10.255.255.1:443?sni=a.com#a",
              "settings": {"timeout": 60}},
    )
    sid = resp.json()["session_id"]
    assert client.post(
        "/api/cancel", json={"session_id": sid}).status_code == 200
    events = read_events(client, sid)
    assert events[-1]["type"] == "done" and events[-1]["cancelled"] is True
