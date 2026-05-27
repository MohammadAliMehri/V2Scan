#!/usr/bin/env python3
"""
V2Ray All-in-One Tools
======================
Combines three tools into one script:

  iran      Check proxy hosts against linkirani.ir (Iran-registered hosts)
  delay     Test config latency with sing-box + curl (CLI dashboard)
  web       Start the V2Ray Checker PRO web UI
  pipeline  Run iran check, then delay test on matched configs

Examples:
  python v2_all_in_one.py iran -i configs.txt
  python v2_all_in_one.py delay -i configs.txt --parallel 5
  python v2_all_in_one.py web --port 8686
  python v2_all_in_one.py pipeline -i configs.txt
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import http.server
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import OrderedDict, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse, urlunparse

# ─── Optional deps (auto-install) ───────────────────────────────────────────

def _ensure_deps(*packages: str) -> None:
    missing = []
    for pkg in packages:
        try:
            __import__(pkg.split("[")[0].replace("-", "_"))
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"Installing: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])


_ensure_deps("rich")
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn
from rich.table import Table

console = Console()

# ─── Shared constants ───────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROXY_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://")
IRAN_API_URL = "https://api.linkirani.ir/shortlink"
DEFAULT_PROBE = "https://www.google.com/generate_204"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0) Edge/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/605.1.15",
    "Mozilla/5.0 (Android 14; Mobile) Chrome/120.0.0.0 Mobile Safari/537.37",
]

PROTOCOL_ORDER = {"vless": 0, "vmess": 1, "trojan": 2, "ss": 3}

# ─── Shared utils ───────────────────────────────────────────────────────────

def b64d(s: str) -> str:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode(errors="ignore")


def b64e(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def format_time(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"


def get_protocol(link: str) -> str:
    if link.startswith("vless://"):
        return "vless"
    if link.startswith("vmess://"):
        return "vmess"
    if link.startswith("trojan://"):
        return "trojan"
    if link.startswith("ss://"):
        return "ss"
    return "unknown"


def get_protocol_emoji(link: str) -> str:
    return {
        "vless": "🟦",
        "vmess": "🟪",
        "trojan": "🟧",
        "ss": "🟩",
    }.get(get_protocol(link), "⬜")


def read_proxy_links(path: str) -> List[str]:
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip().startswith(PROXY_PREFIXES)]


def random_headers() -> Dict[str, str]:
    return {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://linkirani.ir",
        "Referer": "https://linkirani.ir/",
        "User-Agent": random.choice(USER_AGENTS),
        "DNT": "1",
        "Connection": "keep-alive",
    }


def get_config_hash(link: str) -> str:
    try:
        if link.startswith(("vless://", "trojan://")):
            u = urlparse(link)
            clean_url = f"{u.scheme}://{u.username}@{u.hostname}:{u.port}{u.path}?{u.query}"
            return hashlib.md5(clean_url.encode()).hexdigest()
        if link.startswith("vmess://"):
            j = json.loads(b64d(link[8:]))
            j.pop("ps", None)
            key_fields = json.dumps(
                {k: v for k, v in sorted(j.items()) if k not in ["ps", "class"]},
                sort_keys=True,
            )
            return hashlib.md5(key_fields.encode()).hexdigest()
        if link.startswith("ss://"):
            return hashlib.md5(link.split("#")[0].encode()).hexdigest()
    except Exception:
        pass
    return hashlib.md5(link.encode()).hexdigest()


def remove_duplicates(links: List[str]) -> Tuple[List[str], int]:
    seen = OrderedDict()
    for link in links:
        seen.setdefault(get_config_hash(link), link)
    unique = list(seen.values())
    return unique, len(links) - len(unique)


def extract_host(link: str) -> Optional[str]:
    try:
        if link.startswith(("vless://", "trojan://")):
            return urlparse(link).hostname
        if link.startswith("vmess://"):
            j = json.loads(b64d(link[8:]))
            return j.get("add") or j.get("host")
        if link.startswith("ss://"):
            raw = link[5:].split("#")[0]
            if "@" not in raw:
                raw = b64d(raw)
            if "@" in raw:
                return raw.split("@")[1].split(":")[0].split("/")[0]
    except Exception:
        pass
    return None


def extract_server_info(link: str) -> dict:
    try:
        if link.startswith("vmess://"):
            raw = b64d(link[8:]).strip()
            if raw.startswith("{"):
                j = json.loads(raw)
                return {
                    "server": j.get("add", ""),
                    "port": int(j.get("port", 0)),
                    "remark": j.get("ps", ""),
                }
        if link.startswith(("vless://", "trojan://")):
            u = urlparse(link)
            return {
                "server": u.hostname or "",
                "port": u.port or 443,
                "remark": unquote(u.fragment) if u.fragment else "",
            }
    except Exception:
        pass
    return {"server": "", "port": 0, "remark": ""}


def parse_outbound(link: str) -> dict:
    try:
        if link.startswith("vless://"):
            u = urlparse(link)
            q = parse_qs(u.query)
            outbound = {
                "type": "vless",
                "tag": "out",
                "server": u.hostname,
                "server_port": u.port or 443,
                "uuid": u.username,
                "flow": q.get("flow", [""])[0] if q.get("flow") else "",
            }
            security = q.get("security", ["none"])[0]
            if security == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": q.get("sni", [u.hostname])[0],
                    "insecure": q.get("allowInsecure", ["0"])[0] == "1",
                }
            elif security == "reality":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": q.get("sni", [u.hostname])[0],
                    "reality": {
                        "enabled": True,
                        "public_key": q.get("pbk", [""])[0],
                        "short_id": q.get("sid", [""])[0],
                    },
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                }
            transport = q.get("type", ["tcp"])[0]
            if transport == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": q.get("path", ["/"])[0],
                    "headers": {"Host": q.get("host", [u.hostname])[0]},
                }
            elif transport == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": q.get("serviceName", [""])[0],
                }
            return outbound

        if link.startswith("trojan://"):
            u = urlparse(link)
            q = parse_qs(u.query)
            password = unquote(u.username) if u.username else ""
            outbound = {
                "type": "trojan",
                "tag": "out",
                "server": u.hostname,
                "server_port": u.port or 443,
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": q.get("sni", [u.hostname])[0],
                    "insecure": q.get("allowInsecure", ["0"])[0] == "1",
                },
            }
            transport = q.get("type", ["tcp"])[0]
            if transport == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": q.get("path", ["/"])[0],
                    "headers": {"Host": q.get("host", [u.hostname])[0]},
                }
            elif transport == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": q.get("serviceName", [""])[0],
                }
            return outbound

        if link.startswith("vmess://"):
            raw = b64d(link[8:]).strip()
            if not raw.startswith("{"):
                raise ValueError("bad vmess")
            j = json.loads(raw)
            outbound = {
                "type": "vmess",
                "tag": "out",
                "server": j.get("add", j.get("host", "")),
                "server_port": int(j.get("port", 443)),
                "uuid": j.get("id"),
                "security": j.get("scy", "auto"),
                "alter_id": int(j.get("aid", 0)),
            }
            if j.get("tls") == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": j.get("sni", j.get("host", j.get("add"))),
                }
            net = j.get("net", "tcp")
            if net == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": j.get("path", "/"),
                    "headers": {"Host": j.get("host", j.get("add"))},
                }
            elif net == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": j.get("path", ""),
                }
            elif net == "h2":
                outbound["transport"] = {
                    "type": "http",
                    "path": j.get("path", "/"),
                    "host": [j.get("host", j.get("add"))],
                }
            return outbound

        raise ValueError("unsupported protocol")
    except Exception as exc:
        raise ValueError(f"parse error: {exc}") from exc


def set_remark(link: str, delay: int) -> str:
    tag = f"🚀{delay}ms"
    if link.startswith(("vless://", "trojan://")):
        u = urlparse(link)
        return urlunparse((u.scheme, u.netloc, u.path, u.params, u.query, tag))
    if link.startswith("vmess://"):
        try:
            j = json.loads(b64d(link[8:]))
            j["ps"] = tag
            return "vmess://" + b64e(json.dumps(j, ensure_ascii=False, separators=(",", ":")))
        except Exception:
            return link
    return link


def build_singbox_cfg(outbound: dict, port: int) -> dict:
    return {
        "log": {"level": "error"},
        "dns": {"servers": [{"tag": "google", "address": "8.8.8.8"}]},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": port,
            "sniff": False,
        }],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "rules": [],
            "final": "out",
            "auto_detect_interface": True,
        },
    }


async def ensure_singbox(singbox: str) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            singbox, "version", stdout=asyncio.subprocess.DEVNULL
        )
        await proc.wait()
        return True
    except Exception:
        return False


async def test_one_delay(
    link: str,
    singbox: str,
    probe: str,
    timeout: int,
    startup_wait: float,
) -> Tuple[bool, int, str]:
    emoji = get_protocol_emoji(link)
    try:
        outbound = parse_outbound(link)
    except Exception:
        return False, 0, link

    port = free_port()
    cfg = build_singbox_cfg(outbound, port)
    proc = None

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.json")
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)

            proc = await asyncio.create_subprocess_exec(
                singbox, "run", "-c", cfg_path, "--disable-color",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            await asyncio.sleep(startup_wait)

            t0 = time.time()
            curl = await asyncio.create_subprocess_exec(
                "curl",
                "--socks5-hostname", f"127.0.0.1:{port}",
                "-L", "--fail", "-s",
                "-w", "%{http_code}",
                "--connect-timeout", str(timeout // 2),
                "--max-time", str(timeout),
                "-o", os.devnull,
                probe,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await curl.communicate()
            delay = int((time.time() - t0) * 1000)

            if proc:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=1)
                except Exception:
                    proc.kill()

            alive = False
            try:
                http_code = int(stdout.decode().strip())
                alive = 200 <= http_code < 400
            except Exception:
                pass
            if not alive and curl.returncode == 0:
                alive = True

            if alive:
                return True, delay, set_remark(link, delay)
            return False, 0, link
    except Exception:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        return False, 0, link


# ─── Iran host checker ──────────────────────────────────────────────────────

class IranStats:
    def __init__(self):
        self.total_hosts = 0
        self.done_hosts = 0
        self.total_configs = 0
        self.matched_configs = 0
        self.failed_configs = 0
        self.invalid_configs = 0
        self.api_errors = 0
        self.start_time: Optional[float] = None
        self.matched_hosts: List[str] = []

    def progress(self) -> float:
        return (self.done_hosts / self.total_hosts * 100) if self.total_hosts else 0

    def elapsed(self) -> str:
        if not self.start_time:
            return "0s"
        return format_time(time.time() - self.start_time)

    def eta(self) -> str:
        if not self.start_time or self.done_hosts == 0:
            return "calculating..."
        elapsed = time.time() - self.start_time
        rate = self.done_hosts / elapsed
        remaining = (self.total_hosts - self.done_hosts) / rate if rate > 0 else 0
        return format_time(remaining)

    def speed(self) -> str:
        if not self.start_time or self.done_hosts == 0:
            return "0/s"
        return f"{self.done_hosts / (time.time() - self.start_time):.1f}/s"


def iran_dashboard(stats: IranStats) -> Table:
    table = Table(
        title=f"🌐 Iran Host Checker • {datetime.now().strftime('%H:%M:%S')}",
        expand=True,
        show_edge=False,
    )
    table.add_column("Metric", style="cyan", width=22)
    table.add_column("Value", style="white")

    pct = stats.progress()
    bar = "█" * int(pct / 2.5) + "░" * (40 - int(pct / 2.5))
    table.add_row("Progress (Hosts)", f"{bar} {pct:.1f}%")
    table.add_row("Hosts Checked", f"{stats.done_hosts}/{stats.total_hosts}")
    table.add_row("Speed", stats.speed())
    table.add_row("Elapsed", stats.elapsed())
    table.add_row("ETA", stats.eta())
    table.add_row("", "")
    table.add_row("Total Configs", str(stats.total_configs))
    table.add_row("Matched Configs", f"[green]{stats.matched_configs}[/green]")
    table.add_row("Not Matched", f"[red]{stats.failed_configs}[/red]")
    table.add_row("Invalid Configs", f"[yellow]{stats.invalid_configs}[/yellow]")
    table.add_row("API Errors", f"[bold yellow]{stats.api_errors}[/bold yellow]")
    if stats.matched_hosts:
        table.add_row("", "")
        table.add_row("Recent Matches", "\n".join(reversed(stats.matched_hosts[-5:])))
    return table


async def check_host_blocking(client, host: str, stats: IranStats, max_attempts: int = 3) -> bool:
    import httpx

    for attempt in range(max_attempts):
        try:
            response = await client.post(
                IRAN_API_URL,
                headers=random_headers(),
                json={"url": host},
                timeout=10,
            )
            if response.status_code == 429:
                await asyncio.sleep(2 ** attempt + random.uniform(0, 1))
                continue
            if response.status_code != 200:
                await asyncio.sleep(1)
                continue

            data = response.json()
            is_registered = data.get("isRegistered") is True
            is_iran_ip = data.get("ipCountryCode", "").lower() == "ir"
            is_in_iran = data.get("isInIran") is True
            return is_registered and is_iran_ip and is_in_iran
        except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError):
            if attempt < max_attempts - 1:
                await asyncio.sleep(2 ** attempt + random.uniform(0, 1))
            else:
                stats.api_errors += 1
        except Exception:
            stats.api_errors += 1
            break
    return False


async def process_iran_host(
    host: str,
    host_to_links: dict,
    sem: asyncio.Semaphore,
    client,
    matched_links: List[str],
    stats: IranStats,
    progress: Progress,
    task_id: int,
    retry: int,
):
    async with sem:
        blocked = await check_host_blocking(client, host, stats, max_attempts=retry + 1)
        stats.done_hosts += 1
        links = host_to_links[host]

        if blocked:
            matched_links.extend(links)
            stats.matched_configs += len(links)
            stats.matched_hosts.append(f"{get_protocol_emoji(links[0])} {host[:40]}")
        else:
            stats.failed_configs += len(links)

        progress.update(task_id, advance=1)


async def run_iran_checker(args: argparse.Namespace) -> int:
    _ensure_deps("httpx[http2]")
    import httpx

    console.print(Panel.fit("[bold cyan]Iran Host Checker[/bold cyan]", border_style="blue"))

    try:
        all_links = read_proxy_links(args.input)
    except FileNotFoundError:
        console.print(f"[red]File not found: {args.input}[/red]")
        return 1

    if not all_links:
        console.print("[red]No valid proxy links found[/red]")
        return 1

    if args.keep_duplicates:
        unique_links, dup_count = all_links, 0
    else:
        unique_links, dup_count = remove_duplicates(all_links)

    stats = IranStats()
    host_to_links: dict = defaultdict(list)
    for link in unique_links:
        host = extract_host(link)
        if host:
            host_to_links[host].append(link)
        else:
            stats.invalid_configs += 1

    unique_hosts = list(host_to_links.keys())
    stats.total_configs = len(unique_links)
    stats.total_hosts = len(unique_hosts)
    stats.start_time = time.time()

    if not unique_hosts:
        console.print("[yellow]No valid hosts to check[/yellow]")
        return 1

    info = Table(show_header=False, show_edge=False)
    info.add_column("", style="cyan")
    info.add_column("", style="white")
    info.add_row("Input file", args.input)
    info.add_row("Total configs", str(len(all_links)))
    if dup_count:
        info.add_row("Duplicates removed", str(dup_count))
    info.add_row("Unique configs", str(len(unique_links)))
    info.add_row("Unique hosts", str(stats.total_hosts))
    info.add_row("Concurrent", str(args.threads))
    info.add_row("Retries", str(args.retry))
    console.print(Panel(info, title="Configuration", border_style="green"))
    console.print("\n[yellow]Starting scan in 2 seconds...[/yellow]\n")
    await asyncio.sleep(2)

    matched_links: List[str] = []

    async with httpx.AsyncClient(
        limits=httpx.Limits(max_connections=args.threads, max_keepalive_connections=20),
        timeout=15.0,
        http2=True,
    ) as client:
        sem = asyncio.Semaphore(args.threads)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total} hosts"),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("[cyan]Checking unique hosts...", total=stats.total_hosts)
            with Live(iran_dashboard(stats), console=console, refresh_per_second=4) as live:
                async def update_live():
                    while stats.done_hosts < stats.total_hosts:
                        live.update(iran_dashboard(stats))
                        await asyncio.sleep(0.25)
                    live.update(iran_dashboard(stats))

                display_task = asyncio.create_task(update_live())
                await asyncio.gather(*[
                    process_iran_host(
                        host, host_to_links, sem, client, matched_links, stats,
                        progress, task_id, args.retry,
                    )
                    for host in unique_hosts
                ])
                await display_task

    final = Table(title="Final Report", expand=True)
    final.add_column("Metric", style="cyan")
    final.add_column("Value", style="white")
    final.add_row("Unique hosts checked", str(stats.total_hosts))
    final.add_row("Total configs processed", str(stats.total_configs))
    final.add_row("Matched configs (Iran)", f"[green]{len(matched_links)}[/green]")
    final.add_row("Not matched", f"[red]{stats.failed_configs}[/red]")
    final.add_row("Invalid configs", f"[yellow]{stats.invalid_configs}[/yellow]")
    final.add_row("API errors", f"[bold yellow]{stats.api_errors}[/bold yellow]")
    final.add_row("Time taken", stats.elapsed())
    final.add_row("Avg speed", stats.speed())
    console.print(final)

    if matched_links:
        matched_links.sort(key=lambda x: PROTOCOL_ORDER.get(get_protocol(x), 4))
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("\n".join(matched_links))
        console.print(f"\n[green]Saved {len(matched_links)} matched configs →[/green] [cyan]{args.out}[/cyan]")
    else:
        console.print("\n[yellow]No Iran-registered hosts found[/yellow]")

    console.print("\n[bold green]Scan completed![/bold green]")
    return 0


# ─── Delay checker (CLI) ────────────────────────────────────────────────────

class DelayStats:
    def __init__(self, total: int, parallel: int):
        self.total = total
        self.parallel = parallel
        self.done = 0
        self.alive = 0
        self.dead = 0
        self.testing = 0
        self.delays: List[int] = []
        self.start_time = time.time()
        self.recent: List[str] = []

    def start_test(self):
        self.testing += 1

    def finish_test(self, alive: bool, delay: int = 0, emoji: str = "⬜"):
        self.done += 1
        self.testing -= 1
        if alive:
            self.alive += 1
            if delay > 0:
                self.delays.append(delay)
            self.recent.append(f"[green]✅ {emoji} {delay:4d}ms[/green]")
        else:
            self.dead += 1
            self.recent.append(f"[red]❌ {emoji} Failed/Timeout[/red]")
        if len(self.recent) > 8:
            self.recent.pop(0)


def delay_dashboard(stats: DelayStats) -> Table:
    table = Table(
        title=f"🚀 V2Ray Delay Checker • {datetime.now().strftime('%H:%M:%S')}",
        expand=True,
        show_edge=False,
    )
    table.add_column("Metric", style="cyan", width=24)
    table.add_column("Value", style="white")

    elapsed = time.time() - stats.start_time
    progress = (stats.done / stats.total * 100) if stats.total else 0
    bar = "█" * int(progress / 2.5) + "░" * (40 - int(progress / 2.5))
    eta = format_time((stats.total - stats.done) / (stats.done / elapsed)) if stats.done else "calculating..."

    table.add_row("Progress", f"{bar} {progress:.1f}%")
    table.add_row("Status", f"{stats.done}/{stats.total} checked | Testing: {stats.testing}/{stats.parallel}")
    table.add_row("Speed", f"{stats.done / elapsed:.1f}/s" if elapsed > 0 else "0/s")
    table.add_row("Elapsed", format_time(elapsed))
    table.add_row("ETA", eta)
    table.add_row("", "")
    table.add_row("✅ Alive", f"[green]{stats.alive}[/green] ({stats.alive / max(stats.done, 1) * 100:.1f}%)")
    table.add_row("❌ Dead", f"[red]{stats.dead}[/red]")
    if stats.delays:
        avg = sum(stats.delays) / len(stats.delays)
        table.add_row("", "")
        table.add_row("Delay Stats", "")
        table.add_row("  Min", f"[cyan]{min(stats.delays)}ms[/cyan]")
        table.add_row("  Avg", f"[cyan]{avg:.0f}ms[/cyan]")
        table.add_row("  Max", f"[cyan]{max(stats.delays)}ms[/cyan]")
    if stats.recent:
        table.add_row("", "")
        table.add_row("Recent Results", "\n".join(stats.recent))
    return table


async def test_one_with_stats(
    link: str,
    singbox: str,
    probe: str,
    timeout: int,
    startup_wait: float,
    stats: DelayStats,
) -> Tuple[bool, int, str]:
    stats.start_test()
    emoji = get_protocol_emoji(link)
    ok, delay, result = await test_one_delay(link, singbox, probe, timeout, startup_wait)
    stats.finish_test(ok, delay if ok else 0, emoji)
    return ok, delay, result


async def run_delay_checker(args: argparse.Namespace) -> int:
    if not await ensure_singbox(args.singbox):
        console.print(f"[red]❌ sing-box not found: {args.singbox}[/red]")
        return 1

    try:
        links = [
            line for line in read_proxy_links(args.input)
            if line.startswith(("vless://", "vmess://", "trojan://"))
        ]
    except FileNotFoundError:
        console.print(f"[red]File not found: {args.input}[/red]")
        return 1

    if not links:
        console.print("[red]❌ No valid links (vless/vmess/trojan)[/red]")
        return 1

    protocol_count = defaultdict(int)
    for link in links:
        protocol_count[get_protocol(link)] += 1

    console.print(Panel("[bold cyan]V2Ray Delay Checker[/bold cyan]", border_style="blue"))
    console.print(f"📁 Input: {args.input} | 📊 Total: {len(links)}")
    console.print(
        f"   🟦 VLESS: {protocol_count['vless']} | "
        f"🟪 VMess: {protocol_count['vmess']} | "
        f"🟧 Trojan: {protocol_count['trojan']}"
    )
    console.print(f"⚡ Parallel: {args.parallel} | 🌐 Probe: {args.probe}")
    console.print("\n[yellow]Starting in 2 seconds...[/yellow]\n")
    await asyncio.sleep(2)

    stats = DelayStats(len(links), args.parallel)
    live: List[Tuple[int, str]] = []
    sem = asyncio.Semaphore(args.parallel)

    async def worker(link: str):
        async with sem:
            ok, delay, new_link = await test_one_with_stats(
                link, args.singbox, args.probe, args.timeout, args.startup_wait, stats
            )
            if ok:
                live.append((delay, new_link))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("[cyan]Testing configs...", total=len(links))
        with Live(delay_dashboard(stats), console=console, refresh_per_second=5) as live_dash:
            async def updater():
                while stats.done < stats.total:
                    live_dash.update(delay_dashboard(stats))
                    progress.update(task, completed=stats.done)
                    await asyncio.sleep(0.2)
                live_dash.update(delay_dashboard(stats))
                progress.update(task, completed=stats.done)

            updater_task = asyncio.create_task(updater())
            await asyncio.gather(*[worker(link) for link in links])
            await updater_task

    live.sort(key=lambda item: item[0])
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(item[1] for item in live))

    elapsed = time.time() - stats.start_time
    console.print("\n[bold]✨ FINAL REPORT ✨[/bold]")
    console.print(
        f"Total tested: {stats.total} | Live: [green]{stats.alive}[/green] | Dead: [red]{stats.dead}[/red]"
    )
    console.print(f"Time: {format_time(elapsed)} | Speed: {stats.total / elapsed:.1f}/s")
    if stats.delays:
        console.print(
            f"Delays → Min: {min(stats.delays)}ms | "
            f"Avg: {sum(stats.delays) / len(stats.delays):.0f}ms | "
            f"Max: {max(stats.delays)}ms"
        )
    if live:
        console.print(f"[green]💾 Saved {len(live)} configs → {args.out}[/green]")
        console.print("\n[bold]Top 3 fastest:[/bold]")
        for i, (delay, cfg) in enumerate(live[:3], 1):
            console.print(f"   {i}. {get_protocol_emoji(cfg)} {delay}ms")
    else:
        console.print("[yellow]⚠️ No live configs[/yellow]")
    return 0


# ─── Web UI ─────────────────────────────────────────────────────────────────

web_sessions: dict = {}


class WebSession:
    def __init__(self, session_id: str, links: List[str], settings: dict):
        self.session_id = session_id
        self.links = links
        self.settings = settings
        self.total = len(links)
        self.done = 0
        self.alive = 0
        self.dead = 0
        self.testing = 0
        self.delays: List[int] = []
        self.results: List[dict] = []
        self.live_configs: List[Tuple[int, str, str]] = []
        self.start_time: Optional[float] = None
        self.running = False
        self.cancelled = False
        self.finished = False
        self.events: List[str] = []
        self.protocol_counts = defaultdict(int)
        for link in links:
            self.protocol_counts[get_protocol(link)] += 1

    def push_event(self, event_type: str, data: dict):
        data["type"] = event_type
        self.events.append(json.dumps(data))

    def get_stats(self) -> dict:
        elapsed = time.time() - self.start_time if self.start_time else 0
        speed = self.done / elapsed if elapsed > 0 else 0
        eta = (self.total - self.done) / speed if speed > 0 else 0
        avg_delay = sum(self.delays) / len(self.delays) if self.delays else 0
        return {
            "total": self.total,
            "done": self.done,
            "alive": self.alive,
            "dead": self.dead,
            "testing": self.testing,
            "elapsed": round(elapsed, 1),
            "speed": round(speed, 2),
            "eta": round(eta, 1),
            "progress": round(self.done / self.total * 100, 1) if self.total else 0,
            "min_delay": min(self.delays) if self.delays else 0,
            "avg_delay": round(avg_delay),
            "max_delay": max(self.delays) if self.delays else 0,
            "running": self.running,
            "finished": self.finished,
            "cancelled": self.cancelled,
            "protocol_counts": dict(self.protocol_counts),
        }


async def test_one_web(
    link: str,
    singbox: str,
    probe: str,
    timeout: int,
    wait: float,
    session: WebSession,
) -> None:
    if session.cancelled:
        return

    session.testing += 1
    info = extract_server_info(link)
    proto = get_protocol(link)

    try:
        outbound = parse_outbound(link)
    except Exception:
        session.done += 1
        session.dead += 1
        session.testing -= 1
        result = {
            "index": session.done,
            "protocol": proto,
            "server": info["server"],
            "port": info["port"],
            "remark": info["remark"],
            "status": "dead",
            "delay": 0,
            "error": "Parse error",
        }
        session.results.append(result)
        session.push_event("result", result)
        session.push_event("stats", session.get_stats())
        return

    port = free_port()
    cfg = build_singbox_cfg(outbound, port)
    proc = None

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.json")
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)

            proc = await asyncio.create_subprocess_exec(
                singbox, "run", "-c", cfg_path, "--disable-color",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            await asyncio.sleep(wait)

            if session.cancelled:
                if proc:
                    proc.kill()
                session.testing -= 1
                return

            t0 = time.time()
            curl = await asyncio.create_subprocess_exec(
                "curl",
                "--socks5-hostname", f"127.0.0.1:{port}",
                "-L", "--fail", "-s",
                "-w", "%{http_code}",
                "--connect-timeout", str(timeout // 2),
                "--max-time", str(timeout),
                "-o", os.devnull,
                probe,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await curl.communicate()
            delay = int((time.time() - t0) * 1000)

            if proc:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=1)
                except Exception:
                    proc.kill()

            alive = False
            try:
                http_code = int(stdout.decode().strip())
                alive = 200 <= http_code < 400
            except Exception:
                pass
            if not alive and curl.returncode == 0:
                alive = True

            session.done += 1
            session.testing -= 1

            if alive:
                session.alive += 1
                session.delays.append(delay)
                remarked = set_remark(link, delay)
                session.live_configs.append((delay, remarked, link))
                result = {
                    "index": session.done,
                    "protocol": proto,
                    "server": info["server"],
                    "port": info["port"],
                    "remark": info["remark"],
                    "status": "alive",
                    "delay": delay,
                }
            else:
                session.dead += 1
                result = {
                    "index": session.done,
                    "protocol": proto,
                    "server": info["server"],
                    "port": info["port"],
                    "remark": info["remark"],
                    "status": "dead",
                    "delay": 0,
                }

            session.results.append(result)
            session.push_event("result", result)
            session.push_event("stats", session.get_stats())
    except Exception:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        session.done += 1
        session.dead += 1
        session.testing -= 1
        result = {
            "index": session.done,
            "protocol": proto,
            "server": info["server"],
            "port": info["port"],
            "remark": info["remark"],
            "status": "dead",
            "delay": 0,
            "error": "Test error",
        }
        session.results.append(result)
        session.push_event("result", result)
        session.push_event("stats", session.get_stats())


async def run_web_checker(session: WebSession):
    session.start_time = time.time()
    session.running = True
    session.push_event("started", session.get_stats())

    settings = session.settings
    singbox = settings.get("singbox_path", "sing-box")
    parallel = settings.get("parallel", 5)
    timeout = settings.get("timeout", 15)
    wait = settings.get("startup_wait", 2.0)
    probe = settings.get("probe_url", DEFAULT_PROBE)

    sem = asyncio.Semaphore(parallel)

    async def worker(link: str):
        async with sem:
            await test_one_web(link, singbox, probe, timeout, wait, session)

    await asyncio.gather(*[worker(link) for link in session.links])
    session.running = False
    session.finished = True
    session.live_configs.sort(key=lambda item: item[0])
    session.push_event("finished", session.get_stats())


def start_web_checker_thread(session: WebSession):
    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_web_checker(session))
        loop.close()

    threading.Thread(target=run, daemon=True).start()


class V2CheckerHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self.serve_html()
        elif path == "/api/status":
            self.handle_status()
        elif path.startswith("/api/events/"):
            self.handle_sse(path)
        elif path.startswith("/api/export/"):
            self.handle_export(path)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = self.path.split("?")[0]
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else ""

        if path == "/api/start":
            self.handle_start(body)
        elif path == "/api/cancel":
            self.handle_cancel(body)
        elif path == "/api/fetch-url":
            self.handle_fetch_url(body)
        else:
            self.send_response(404)
            self.end_headers()

    def handle_start(self, body):
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, 400)
            return

        configs_text = data.get("configs", "")
        settings = data.get("settings", {})
        links = [
            line.strip() for line in configs_text.strip().split("\n")
            if line.strip().startswith(PROXY_PREFIXES)
        ]
        if not links:
            self.send_json({"error": "No valid configs found"}, 400)
            return

        sid = str(uuid.uuid4())[:8]
        session = WebSession(sid, links, settings)
        web_sessions[sid] = session
        start_web_checker_thread(session)
        self.send_json({"session_id": sid, "total": len(links), "protocols": dict(session.protocol_counts)})

    def handle_cancel(self, body):
        try:
            data = json.loads(body)
            sid = data.get("session_id", "")
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, 400)
            return

        session = web_sessions.get(sid)
        if session:
            session.cancelled = True
            self.send_json({"ok": True})
        else:
            self.send_json({"error": "Session not found"}, 404)

    def handle_status(self):
        sid = self.path.split("session_id=")[-1] if "session_id=" in self.path else ""
        session = web_sessions.get(sid)
        if session:
            self.send_json(session.get_stats())
        else:
            self.send_json({"error": "No session"}, 404)

    def handle_sse(self, path):
        sid = path.split("/")[-1]
        session = web_sessions.get(sid)
        if not session:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        last_idx = 0
        try:
            while True:
                while last_idx < len(session.events):
                    evt = session.events[last_idx]
                    self.wfile.write(f"data: {evt}\n\n".encode())
                    self.wfile.flush()
                    last_idx += 1

                if session.finished or session.cancelled:
                    final_data = json.dumps({"type": "done", **session.get_stats()})
                    self.wfile.write(f"data: {final_data}\n\n".encode())
                    self.wfile.flush()
                    break
                time.sleep(0.15)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def handle_export(self, path):
        parts = path.split("/")
        if len(parts) < 4:
            self.send_response(400)
            self.end_headers()
            return

        sid = parts[3]
        fmt = parts[4] if len(parts) > 4 else "txt"
        session = web_sessions.get(sid)
        if not session:
            self.send_json({"error": "Session not found"}, 404)
            return

        session.live_configs.sort(key=lambda item: item[0])

        if fmt == "txt":
            text = "\n".join(item[1] for item in session.live_configs)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Disposition", "attachment; filename=live_configs.txt")
            self.send_header("Content-Length", str(len(text.encode())))
            self.end_headers()
            self.wfile.write(text.encode())
        elif fmt == "json":
            data = []
            for delay, remarked, original in session.live_configs:
                info = extract_server_info(original)
                data.append({
                    "delay": delay,
                    "protocol": get_protocol(original),
                    "server": info["server"],
                    "port": info["port"],
                    "remark": info["remark"],
                    "config": remarked,
                })
            text = json.dumps(data, indent=2, ensure_ascii=False)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=live_configs.json")
            self.send_header("Content-Length", str(len(text.encode())))
            self.end_headers()
            self.wfile.write(text.encode())
        elif fmt == "clipboard":
            text = "\n".join(item[1] for item in session.live_configs)
            self.send_json({"configs": text, "count": len(session.live_configs)})
        else:
            self.send_response(400)
            self.end_headers()

    def handle_fetch_url(self, body):
        try:
            data = json.loads(body)
            url = data.get("url", "").strip()
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, 400)
            return

        if not url:
            self.send_json({"error": "URL is required"}, 400)
            return

        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "V2RayChecker/2.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
        except Exception as exc:
            self.send_json({"error": f"Failed to fetch: {exc}"}, 500)
            return

        try:
            decoded = base64.b64decode(raw.strip() + "==").decode("utf-8", errors="ignore")
            if any(prefix in decoded for prefix in PROXY_PREFIXES):
                raw = decoded
        except Exception:
            pass

        lines = [
            line.strip() for line in raw.split("\n")
            if line.strip().startswith(PROXY_PREFIXES)
        ]
        self.send_json({"configs": "\n".join(lines), "count": len(lines)})

    def serve_html(self):
        html_path = os.path.join(SCRIPT_DIR, "index.html")
        try:
            with open(html_path, "r", encoding="utf-8") as f:
                html = f.read()
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"index.html not found (place it next to v2_all_in_one.py)")


def run_web_ui(args: argparse.Namespace) -> int:
    server = http.server.HTTPServer((args.host, args.port), V2CheckerHandler)
    console.print(Panel("[bold cyan]V2Ray Checker PRO — Web UI[/bold cyan]", border_style="blue"))
    console.print(f"  Server: [cyan]http://{args.host}:{args.port}[/cyan]")
    console.print("  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[red]Server stopped.[/red]")
        server.server_close()
    return 0


# ─── Pipeline (iran → delay) ────────────────────────────────────────────────

async def run_pipeline(args: argparse.Namespace) -> int:
    console.print(Panel("[bold cyan]Pipeline: Iran Check → Delay Test[/bold cyan]", border_style="blue"))

    iran_args = argparse.Namespace(
        input=args.input,
        threads=args.threads,
        out=args.iran_out,
        keep_duplicates=args.keep_duplicates,
        retry=args.retry,
    )
    console.print("\n[bold]Step 1/2: Iran host check[/bold]")
    iran_code = await run_iran_checker(iran_args)
    if iran_code != 0:
        return iran_code

    if not os.path.exists(args.iran_out) or os.path.getsize(args.iran_out) == 0:
        console.print("[yellow]Pipeline stopped: no matched configs from Iran check[/yellow]")
        return 0

    delay_args = argparse.Namespace(
        input=args.iran_out,
        singbox=args.singbox,
        parallel=args.parallel,
        timeout=args.timeout,
        startup_wait=args.startup_wait,
        probe=args.probe,
        out=args.out,
    )
    console.print("\n[bold]Step 2/2: Delay test on matched configs[/bold]")
    return await run_delay_checker(delay_args)


# ─── CLI entry point ────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="V2Ray All-in-One Tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    iran = subparsers.add_parser("iran", help="Check hosts against linkirani.ir API")
    iran.add_argument("-i", "--input", required=True, help="Input file with proxy links")
    iran.add_argument("--threads", type=int, default=100, help="Concurrent requests (default: 100)")
    iran.add_argument("--out", default="iran_registered.txt", help="Output file")
    iran.add_argument("--keep-duplicates", action="store_true", help="Keep duplicate configs")
    iran.add_argument("--retry", type=int, default=3, help="Retry attempts per host (default: 3)")

    delay = subparsers.add_parser("delay", help="Test config latency with sing-box (CLI)")
    delay.add_argument("-i", "--input", required=True, help="Configs file")
    delay.add_argument("--singbox", default="sing-box", help="sing-box binary path")
    delay.add_argument("--parallel", type=int, default=3, help="Parallel tests (default: 3)")
    delay.add_argument("--timeout", type=int, default=15, help="Timeout in seconds")
    delay.add_argument("--startup-wait", type=float, default=2.0, help="sing-box startup wait")
    delay.add_argument("--probe", default=DEFAULT_PROBE, help="Probe URL")
    delay.add_argument("--out", default="live_with_delay.txt", help="Output file")

    web = subparsers.add_parser("web", help="Start V2Ray Checker PRO web UI")
    web.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    web.add_argument("--port", type=int, default=8686, help="Port (default: 8686)")

    pipeline = subparsers.add_parser("pipeline", help="Iran check then delay test matched configs")
    pipeline.add_argument("-i", "--input", required=True, help="Input file with proxy links")
    pipeline.add_argument("--iran-out", default="iran_registered.txt", help="Intermediate Iran output")
    pipeline.add_argument("--out", default="live_with_delay.txt", help="Final delay output")
    pipeline.add_argument("--threads", type=int, default=100, help="Iran check concurrency")
    pipeline.add_argument("--retry", type=int, default=3, help="Iran check retries")
    pipeline.add_argument("--keep-duplicates", action="store_true", help="Keep duplicate configs")
    pipeline.add_argument("--singbox", default="sing-box", help="sing-box binary path")
    pipeline.add_argument("--parallel", type=int, default=3, help="Delay test parallelism")
    pipeline.add_argument("--timeout", type=int, default=15, help="Delay timeout")
    pipeline.add_argument("--startup-wait", type=float, default=2.0, help="sing-box startup wait")
    pipeline.add_argument("--probe", default=DEFAULT_PROBE, help="Probe URL")

    return parser


async def async_main(args: argparse.Namespace) -> int:
    if args.command == "iran":
        return await run_iran_checker(args)
    if args.command == "delay":
        return await run_delay_checker(args)
    if args.command == "web":
        return run_web_ui(args)
    if args.command == "pipeline":
        return await run_pipeline(args)
    console.print(f"[red]Unknown command: {args.command}[/red]")
    return 1


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")
        return 130
    except Exception as exc:
        console.print(f"\n[red]Error: {exc}[/red]")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
