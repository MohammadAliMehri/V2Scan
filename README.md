# V2Scan

A single Python script for fetching, deduplicating, and latency-testing free public V2Ray configs. Pulls configs from 13+ GitHub sources, tests them through sing-box, and gives you the fastest working proxies.

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
python v2_all_in_one.py fetch

# Fetch + deduplicate + delay-test in one go
python v2_all_in_one.py scan --parallel 5

# Launch the web dashboard
python v2_all_in_one.py web --port 8686
```

Open **http://127.0.0.1:8686** for the web UI.

---

## Files

| File | Purpose |
|------|---------|
| `v2_all_in_one.py` | Main script (all commands) |
| `index.html` | Web UI frontend (used by `web` command) |
| `setup.bat` | Windows one-click setup |
| `setup.sh` | Linux/macOS one-click setup |

---

## Requirements

- **Python 3.8+**
- **sing-box** — required for `delay`, `scan`, `web`, and `pipeline`
- **curl** — required for delay testing
- Internet access

Python packages (`rich`, `httpx`) are installed automatically on first run.

---

## Commands

### `fetch` — Fetch configs from GitHub

Grabs free public V2Ray configs from 13 curated GitHub repos concurrently. No sing-box needed.

```bash
python v2_all_in_one.py fetch
python v2_all_in_one.py fetch --out public.txt --timeout 30
```

| Option | Default | Description |
|--------|---------|-------------|
| `--out` | `fetched_public.txt` | Output file |
| `--sources` | *(built-in list)* | Custom raw GitHub URLs |
| `--timeout` | `20` | HTTP timeout per source (sec) |

**Sources include:** barry-far, mfuu, peasoft, mahdibland, soroushmirzaei, Epodonios, yebekhe (13 endpoints total).

---

### `scan` — Fetch + Deduplicate + Delay Test (all-in-one)

The main command. Fetches from GitHub, deduplicates, then runs delay tests on all vless/vmess/trojan configs.

```bash
python v2_all_in_one.py scan
python v2_all_in_one.py scan --parallel 5 --out live.txt
python v2_all_in_one.py scan -i my_configs.txt  # merge with local file
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i`, `--input` | *(none)* | Optional local file to merge |
| `--fetch-out` | `fetched_public.txt` | Output for all fetched configs |
| `--out` | `live_with_delay.txt` | Output for live configs |
| `--singbox` | `sing-box` | sing-box binary path |
| `--parallel` | `3` | Parallel delay tests |
| `--timeout` | `15` | Delay test timeout (sec) |
| `--startup-wait` | `2.0` | sing-box startup wait |
| `--probe` | Google 204 URL | Probe URL |

---

### `delay` — Delay Checker (CLI)

Tests each config through sing-box and measures latency with curl.

```bash
python v2_all_in_one.py delay -i configs.txt
python v2_all_in_one.py delay -i configs.txt --parallel 5 --out live.txt
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i`, `--input` | *(required)* | Configs file |
| `--out` | `live_with_delay.txt` | Output file (sorted by delay) |
| `--singbox` | `sing-box` | sing-box binary path |
| `--parallel` | `3` | Parallel tests |
| `--timeout` | `15` | Curl timeout (sec) |
| `--startup-wait` | `2.0` | Wait for sing-box to start |
| `--probe` | Google 204 URL | Probe URL |

---

### `iran` — Iran Host Checker

Checks each host against the [linkirani.ir](https://linkirani.ir) API. Keeps configs whose servers are Iran-registered.

```bash
python v2_all_in_one.py iran -i configs.txt
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i`, `--input` | *(required)* | Input file |
| `--out` | `iran_registered.txt` | Output file |
| `--threads` | `100` | Concurrent API requests |
| `--retry` | `3` | Retries per host |
| `--keep-duplicates` | off | Do not remove duplicates |

---

### `web` — Web Dashboard

Starts a local web server with a real-time dashboard. Paste configs, fetch from GitHub, or load from file, then scan.

```bash
python v2_all_in_one.py web
python v2_all_in_one.py web --port 8686
```

Open **http://127.0.0.1:8686**

Features:
- **GitHub fetch** — one-click fetch from all 13 sources with dedup
- **URL/Sub** — paste any subscription URL
- **File upload** — drag & drop
- **Live dashboard** — real-time stats, progress, delay chart
- **Export** — download as TXT/JSON or copy to clipboard

---

### `pipeline` — Iran Check + Delay Test

Runs both steps in sequence:

```bash
python v2_all_in_one.py pipeline -i configs.txt
```

---

## Typical Workflow

```bash
# 1. Fetch fresh configs from GitHub
python v2_all_in_one.py fetch --out today.txt

# 2. Test delay on the fetched configs
python v2_all_in_one.py delay -i today.txt --parallel 5 --out live.txt

# Or do both in one command:
python v2_all_in_one.py scan --parallel 5

# Or use the web UI:
python v2_all_in_one.py web --port 8686
```

---

## Supported Protocols

| Protocol | Fetch | Delay Test | Iran Check |
|----------|-------|------------|------------|
| vless:// | ✅ | ✅ | ✅ |
| vmess:// | ✅ | ✅ | ✅ |
| trojan:// | ✅ | ✅ | ✅ |
| ss:// | ✅ | — | ✅ |
| hy2:// / hysteria2:// | ✅ | — | — |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `sing-box not found` | Install sing-box and/or pass `--singbox /path/to/sing-box` |
| `No valid links` | Ensure lines start with `vless://`, `vmess://`, `trojan://`, or `ss://` |
| `index.html not found` | Keep `index.html` next to `v2_all_in_one.py` |
| Slow or many API errors (iran) | Lower `--threads` or increase `--retry` |
| All configs dead (delay) | Check sing-box/curl, try a different `--probe` |

Press **Ctrl+C** to stop any command or the web server.

---

## ⚠️ Disclaimer

Unauthorized use is at your own responsibility.
