# V2Scan

A modular Python package for fetching, deduplicating, and latency-testing free public V2Ray configs. Pulls configs from GitHub sources, tests them through sing-box (many configs per sing-box process), and gives you the fastest working proxies.

> Run commands with `python main.py <command>` (or `python -m v2scan <command>`). `python main.py --help` lists all commands.

## Quick Start

```bash
# Windows
setup.bat

# Linux / macOS
chmod +x setup.sh && ./setup.sh
```

Then:

```bash
# Fetch free configs from GitHub (no sing-box needed)
python main.py fetch

# Fetch + deduplicate + delay-test in one go
python main.py scan --parallel 5

# Launch the web dashboard
python main.py web --port 8686
```

Open **http://127.0.0.1:8686** for the web UI.

---

## Files

| File | Purpose |
|------|---------|
| `main.py` | Entrypoint (`v2scan.cli:main`) |
| `v2scan/cli.py` | CLI commands and dashboards |
| `v2scan/core/` | Models, protocol parsers, dedup, sing-box manager, latency tester |
| `v2scan/services/` | GitHub/subscription fetcher, linkirani checker |
| `v2scan/web/` | FastAPI server, REST/SSE routes, static dashboard |
| `tests/` | pytest suite |
| `setup.bat` / `setup.sh` | One-click setup |

Manual setup with a virtual environment:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt pytest
python -m pytest tests -q
```

> Migrating from v1: `v2_all_in_one.py` and the root `index.html` were removed; use `main.py` (same commands and flags).

---

## Requirements

- **Python 3.10+**
- **sing-box 1.12+** — required for `delay`, `scan`, `web`, and `pipeline` (a copy unpacked in the project folder is auto-detected)
- Internet access

Python packages (`rich`, `httpx[socks,http2]`, `fastapi`, `uvicorn`, `qrcode`) are listed in `requirements.txt` and installed automatically on first run.

---

## Commands

### `fetch` — Fetch configs from GitHub

Grabs free public V2Ray configs from 13 curated GitHub repos concurrently. No sing-box needed.

```bash
python main.py fetch
python main.py fetch --out public.txt --timeout 30
```

| Option | Default | Description |
|--------|---------|-------------|
| `--out` | `fetched_public.txt` | Output file |
| `--sources` | *(built-in list)* | Custom raw GitHub URLs |
| `--timeout` | `20` | HTTP timeout per source (sec) |

**Sources include:** barry-far, mfuu, peasoft, mahdibland, soroushmirzaei, Epodonios, yebekhe (13 endpoints total).

---

### `scan` — Fetch + Deduplicate + Delay Test (all-in-one)

The main command. Fetches from GitHub, deduplicates, then runs delay tests on all supported configs.

```bash
python main.py scan
python main.py scan --parallel 5 --out live.txt
python main.py scan -i my_configs.txt  # merge with local file
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i`, `--input` | *(none)* | Optional local file to merge |
| `--fetch-out` | `fetched_public.txt` | Output for all fetched configs |
| `--out` | `live_with_delay.txt` | Output for live configs |
| `--singbox` | `sing-box` | sing-box binary path |
| `--parallel` | `3` | Concurrent probes |
| `--timeout` | `15` | Delay test timeout (sec) |
| `--startup-wait` | `2.0` | Max wait for sing-box readiness (polled; returns early) |
| `--batch-size` | `40` | Configs tested per sing-box process |
| `--probe` | Google 204 URL | Probe URL |

---

### `delay` — Delay Checker (CLI)

Tests configs in batches: each sing-box process exposes one local SOCKS port per config, and latency is measured with async HTTP probes. A config sing-box rejects is isolated and reported dead without affecting the rest of its batch.

```bash
python main.py delay -i configs.txt
python main.py delay -i configs.txt --parallel 5 --out live.txt
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i`, `--input` | *(required)* | Configs file |
| `--out` | `live_with_delay.txt` | Output file (sorted by delay) |
| `--singbox` | `sing-box` | sing-box binary path |
| `--parallel` | `3` | Concurrent probes |
| `--timeout` | `15` | Probe timeout (sec) |
| `--startup-wait` | `2.0` | Max wait for sing-box readiness |
| `--batch-size` | `40` | Configs tested per sing-box process |
| `--probe` | Google 204 URL | Probe URL |

---

### `iran` — Iran Host Checker

Checks each host against the [linkirani.ir](https://linkirani.ir) API. Keeps configs whose servers are Iran-registered.

```bash
python main.py iran -i configs.txt
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i`, `--input` | *(required)* | Input file |
| `--out` | `iran_registered.txt` | Output file |
| `--threads` | `100` | Concurrent API requests |
| `--retry` | `3` | Retries per host |
| `--rate` | `50` | Max API requests/sec (token bucket; 429 pauses all workers) |
| `--no-geoip` | off | Disable the GeoIP fallback used when the API keeps failing |
| `--keep-duplicates` | off | Do not remove duplicates |

---

### `web` — Web Dashboard

Starts a local web server with a real-time dashboard. Paste configs, fetch from GitHub, or load from file, then scan.

```bash
python main.py web
python main.py web --port 8686
```

Open **http://127.0.0.1:8686**

Features:
- **GitHub fetch** — one-click fetch from all 13 sources with dedup
- **URL/Sub** — paste any subscription URL
- **File upload** — drag & drop
- **Live dashboard** — real-time stats, progress, latency distribution
- **Export** — download as TXT/JSON, copy to clipboard, or use the live `/sub/<session>` subscription link
- **QR codes** — import a single alive config on mobile

API: `POST /api/start`, `GET /api/events/{id}` (SSE), `POST /api/cancel`, `POST /api/fetch-github`, `POST /api/fetch-url`, `GET /api/export/{id}/txt|json`, `GET /sub/{id}`.

---

### `pipeline` — Iran Check + Delay Test

Runs both steps in sequence:

```bash
python main.py pipeline -i configs.txt
```

---

## Typical Workflow

```bash
# 1. Fetch fresh configs from GitHub
python main.py fetch --out today.txt

# 2. Test delay on the fetched configs
python main.py delay -i today.txt --parallel 5 --out live.txt

# Or do both in one command:
python main.py scan --parallel 5

# Or use the web UI:
python main.py web --port 8686
```

---

## Supported Protocols

| Protocol | Fetch | Delay Test | Iran Check |
|----------|-------|------------|------------|
| vless:// | ✅ | ✅ | ✅ |
| vmess:// | ✅ | ✅ | ✅ |
| trojan:// | ✅ | ✅ | ✅ |
| ss:// | ✅ | ✅ | ✅ |
| hy2:// / hysteria2:// | ✅ | ✅ | ✅ |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `sing-box not found` | Install sing-box and/or pass `--singbox /path/to/sing-box` |
| `No valid links` | Ensure lines start with `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://` or `hy2://` |
| `sing-box rejected config` | That config is unsupported by your sing-box version; it is skipped, others continue |
| Slow or many API errors (iran) | Lower `--rate`/`--threads` or increase `--retry` |
| All configs dead (delay) | Check sing-box, try a different `--probe` |

Press **Ctrl+C** to stop any command or the web server.

---

## ⚠️ Disclaimer

Unauthorized use is at your own responsibility.
