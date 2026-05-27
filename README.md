# V2Ray All-in-One Tools

A single Python script for filtering proxy configs by Iran-registered hosts and testing latency with sing-box.

## Files

| File | Purpose |
|------|---------|
| `v2_all_in_one.py` | Main script (all commands) |
| `index.html` | Web UI frontend (used by the `web` command) |

## Requirements

- **Python 3.8+**
- **sing-box** — required for `delay`, `web`, and `pipeline`
- **curl** — required for delay testing
- Internet access for API checks and probe requests

Python packages (`rich`, `httpx`) are installed automatically on first run.

### Install sing-box and curl

**Windows (with [Scoop](https://scoop.sh)):**

```powershell
scoop install sing-box curl
```

**Linux (Debian/Ubuntu):**

```bash
sudo apt install curl
# Install sing-box from https://sing-box.sagernet.org/
```

Verify:

```bash
sing-box version
curl --version
```

## Input format

Create a text file with one proxy link per line. Supported schemes:

- `vless://`
- `vmess://`
- `trojan://`
- `ss://` (Iran checker only)

Example `configs.txt`:

```text
vless://uuid@example.com:443?security=tls&type=ws#MyServer
vmess://eyJhZGQiOiAiZXhhbXBsZS5jb20iLCAicG9ydCI6ICI0NDMifQ==
trojan://password@example.com:443?sni=example.com#Trojan
```

---

## Commands

### 1. Iran host checker (`iran`)

Checks each unique host against the [linkirani.ir](https://linkirani.ir) API and keeps configs whose hosts are registered and located in Iran.

```bash
python v2_all_in_one.py iran -i configs.txt
```

**Common options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-i`, `--input` | *(required)* | Input file with proxy links |
| `--out` | `iran_registered.txt` | Output file for matched configs |
| `--threads` | `100` | Concurrent API requests |
| `--retry` | `3` | Retries per host |
| `--keep-duplicates` | off | Do not remove duplicate configs |

**Example:**

```bash
python v2_all_in_one.py iran -i configs.txt --threads 50 --out filtered.txt
```

---

### 2. Delay checker — CLI (`delay`)

Tests each config through sing-box and measures latency with curl. Live configs are saved with a delay remark (e.g. `🚀142ms`).

Supported protocols: **VLESS**, **VMess**, **Trojan**.

```bash
python v2_all_in_one.py delay -i configs.txt
```

**Common options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-i`, `--input` | *(required)* | Input file with proxy links |
| `--out` | `live_with_delay.txt` | Output file (sorted by delay) |
| `--singbox` | `sing-box` | Path to sing-box binary |
| `--parallel` | `3` | Number of parallel tests |
| `--timeout` | `15` | Curl timeout (seconds) |
| `--startup-wait` | `2.0` | Wait for sing-box to start |
| `--probe` | `https://www.google.com/generate_204` | URL used for latency test |

**Example:**

```bash
python v2_all_in_one.py delay -i configs.txt --parallel 5 --out live.txt
```

---

### 3. Delay checker — Web UI (`web`)

Starts a local web server with a real-time dashboard. Open the URL in your browser, paste configs (or fetch from a subscription URL), and run tests.

```bash
python v2_all_in_one.py web
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `8686` | Port |

Then open: **http://127.0.0.1:8686**

The web UI can export live configs as `.txt`, `.json`, or copy to clipboard.

> `index.html` must stay in the same folder as `v2_all_in_one.py`.

---

### 4. Pipeline (`pipeline`)

Runs both steps in order:

1. **Iran check** → saves matched configs to `--iran-out`
2. **Delay test** → tests only matched configs, saves to `--out`

```bash
python v2_all_in_one.py pipeline -i configs.txt
```

**Example with custom outputs:**

```bash
python v2_all_in_one.py pipeline -i configs.txt --iran-out step1.txt --out step2_live.txt --parallel 5
```

**Pipeline options** (combines `iran` + `delay` settings):

| Option | Default | Description |
|--------|---------|-------------|
| `-i`, `--input` | *(required)* | Input file |
| `--iran-out` | `iran_registered.txt` | Intermediate file after Iran check |
| `--out` | `live_with_delay.txt` | Final file after delay test |
| `--threads` | `100` | Iran check concurrency |
| `--retry` | `3` | Iran check retries |
| `--parallel` | `3` | Delay test parallelism |
| `--singbox` | `sing-box` | sing-box binary path |
| `--timeout` | `15` | Delay timeout |
| `--probe` | Google 204 URL | Probe URL |

---

## Typical workflow

```bash
# Option A: Filter Iran hosts only
python v2_all_in_one.py iran -i my_sub.txt -o iran_only.txt

# Option B: Test delay only
python v2_all_in_one.py delay -i my_sub.txt -o live.txt

# Option C: Filter + test in one go
python v2_all_in_one.py pipeline -i my_sub.txt

# Option D: Use the web UI
python v2_all_in_one.py web --port 8686
```

---

## Help

```bash
python v2_all_in_one.py --help
python v2_all_in_one.py iran --help
python v2_all_in_one.py delay --help
python v2_all_in_one.py web --help
python v2_all_in_one.py pipeline --help
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `sing-box not found` | Install sing-box and/or pass `--singbox /path/to/sing-box` |
| `No valid links` | Ensure lines start with `vless://`, `vmess://`, or `trojan://` |
| `index.html not found` | Keep `index.html` next to `v2_all_in_one.py` for the web UI |
| Slow or many API errors (iran) | Lower `--threads` or increase `--retry` |
| All configs dead (delay) | Check sing-box/curl, try a different `--probe`, or lower `--parallel` |

Press **Ctrl+C** to stop any running command or the web server.

---
## ⁉️ Any unauthorized use is at your own responsibility.
