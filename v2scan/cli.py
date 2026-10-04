"""V2Scan command line interface.

Commands:
  fetch     Fetch free public V2Ray configs from GitHub repos
  scan      Fetch + deduplicate + delay-test in one command
  iran      Check proxy hosts against linkirani.ir (Iran-registered hosts)
  delay     Test config latency with sing-box (CLI dashboard)
  web       Start the V2Scan web dashboard
  pipeline  Run iran check, then delay test on matched configs

Examples:
  python main.py fetch --out public.txt
  python main.py scan --parallel 5
  python main.py iran -i configs.txt
  python main.py delay -i configs.txt --parallel 5
  python main.py web --port 8686
  python main.py pipeline -i configs.txt
"""

from __future__ import annotations

from .core.deps import CORE_REQUIREMENTS, WEB_REQUIREMENTS, ensure_deps

# legacy behaviour: auto-install missing packages
ensure_deps(CORE_REQUIREMENTS)

import argparse  # noqa: E402
import asyncio  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from collections import defaultdict  # noqa: E402
from datetime import datetime  # noqa: E402
from pathlib import Path  # noqa: E402

from rich.console import Console  # noqa: E402
from rich.live import Live  # noqa: E402
from rich.panel import Panel  # noqa: E402
from rich.table import Table  # noqa: E402

from .core.config import (  # noqa: E402
    DEFAULT_BATCH_SIZE,
    DEFAULT_PARALLEL,
    DEFAULT_PROBE,
    DEFAULT_SINGBOX,
    DEFAULT_STARTUP_WAIT,
    DEFAULT_TIMEOUT,
    GITHUB_CONFIG_SOURCES,
    PROTOCOL_EMOJI,
    PROTOCOL_ORDER,
    format_time,
)
from .core.dedup import dedup_links  # noqa: E402
from .core.models import ScanStats, TestResult  # noqa: E402
from .core.parsers import extract_host, extract_proxy_links, get_protocol  # noqa: E402
from .core.singbox import SingBoxInfo, ensure_singbox, kill_all  # noqa: E402
from .core.tester import LatencyTester  # noqa: E402
from .services.fetcher import fetch_sources  # noqa: E402
from .services.iran_checker import IranChecker, IranStats  # noqa: E402

console = Console()


# ─── Helpers ────────────────────────────────────────────────────────────────

def emoji_for(protocol: str) -> str:
    return PROTOCOL_EMOJI.get(protocol, "⬜")


def read_proxy_links(path: str) -> list[str]:
    """Read supported proxy links from a text file (one per line)."""
    return extract_proxy_links(Path(path).read_text(encoding="utf-8", errors="ignore"))


def protocol_counts(links: list[str]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for link in links:
        counts[get_protocol(link)] += 1
    return counts


def protocol_line(counts: dict[str, int]) -> str:
    return " | ".join(
        f"{emoji_for(p)} {p.upper()}: {c}" for p, c in sorted(counts.items(), key=lambda x: -x[1])
    )


def sort_links(links: list[str]) -> list[str]:
    return sorted(links, key=lambda x: (PROTOCOL_ORDER.get(get_protocol(x), 99), x))


def write_lines(path: str, lines: list[str]) -> None:
    Path(path).write_text("\n".join(lines), encoding="utf-8")


async def require_singbox(path: str) -> SingBoxInfo | None:
    info = await ensure_singbox(path)
    if info is None:
        console.print(
            f"[red]❌ sing-box not found or not runnable: {path}[/red]")
    return info


# ─── fetch ──────────────────────────────────────────────────────────────────

async def run_fetch(args: argparse.Namespace) -> int:
    """Fetch free public V2Ray configs from GitHub repos."""
    console.print(
        Panel.fit("[bold cyan]GitHub Config Fetcher[/bold cyan]", border_style="blue"))

    sources = GITHUB_CONFIG_SOURCES
    if args.sources:
        sources = [(url, url.split("/")[-1]) for url in args.sources]

    info = Table(show_header=False, show_edge=False)
    info.add_column("", style="cyan")
    info.add_column("", style="white")
    info.add_row("Sources", str(len(sources)))
    info.add_row("Timeout", f"{args.timeout}s")
    info.add_row("Output", args.out)
    console.print(Panel(info, title="Configuration", border_style="green"))
    console.print("\n[cyan]Fetching configs...[/cyan]\n")

    fetched = await fetch_sources(sources, timeout=args.timeout)

    table = Table(title="Fetch Results", expand=True)
    table.add_column("Source", style="cyan", ratio=3)
    table.add_column("Configs", style="white", justify="right")
    for desc, count in sorted(fetched.source_counts.items(), key=lambda x: -x[1]):
        table.add_row(desc, str(count))
    for err in fetched.errors:
        table.add_row(f"[red]{err}[/red]", "[red]FAILED[/red]")
    console.print(table)

    if not fetched.links:
        console.print("[red]No configs fetched from any source[/red]")
        return 1

    unique, dup_count = dedup_links(fetched.links)
    console.print(
        f"\n[bold]Total fetched: {len(fetched.links)} | Unique: {len(unique)} | "
        f"Duplicates: {dup_count}[/bold]"
    )
    console.print(f"   {protocol_line(protocol_counts(unique))}")

    write_lines(args.out, sort_links(unique))
    console.print(
        f"\n[green]Saved {len(unique)} unique configs → {args.out}[/green]")
    if fetched.errors:
        console.print(
            f"[yellow]Warnings: {len(fetched.errors)} source(s) failed[/yellow]")
    return 0


# ─── iran ───────────────────────────────────────────────────────────────────

def iran_dashboard(stats: IranStats) -> Table:
    table = Table(
        title=f"🌐 Iran Host Checker • {datetime.now().strftime('%H:%M:%S')}",
        expand=True,
        show_edge=False,
    )
    table.add_column("Metric", style="cyan", width=22)
    table.add_column("Value", style="white")
    pct = stats.progress
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
    table.add_row("Invalid Configs",
                  f"[yellow]{stats.invalid_configs}[/yellow]")
    table.add_row(
        "API Errors", f"[bold yellow]{stats.api_errors}[/bold yellow]")
    table.add_row("Rate-limited (429)",
                  f"[yellow]{stats.rate_limited}[/yellow]")
    if stats.geoip_matches:
        table.add_row("GeoIP fallback hits",
                      f"[cyan]{stats.geoip_matches}[/cyan]")
    if stats.matched_hosts:
        table.add_row("", "")
        table.add_row("Recent Matches", "\n".join(
            reversed(stats.matched_hosts[-5:])))
    return table


async def iran_check(args: argparse.Namespace) -> tuple[int, list[str]]:
    """Run the Iran host check, write ``args.out``; returns ``(exit_code, matched_links)``."""
    console.print(
        Panel.fit("[bold cyan]Iran Host Checker[/bold cyan]", border_style="blue"))

    try:
        all_links = read_proxy_links(args.input)
    except FileNotFoundError:
        console.print(f"[red]File not found: {args.input}[/red]")
        return 1, []
    if not all_links:
        console.print("[red]No valid proxy links found[/red]")
        return 1, []

    if args.keep_duplicates:
        unique_links, dup_count = all_links, 0
    else:
        unique_links, dup_count = dedup_links(all_links)

    stats = IranStats()
    host_to_links: dict[str, list[str]] = defaultdict(list)
    for link in unique_links:
        host = extract_host(link)
        if host:
            host_to_links[host].append(link)
        else:
            stats.invalid_configs += 1

    hosts = list(host_to_links)
    stats.total_configs = len(unique_links)
    stats.total_hosts = len(hosts)
    if not hosts:
        console.print("[yellow]No valid hosts to check[/yellow]")
        return 1, []

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
    info.add_row("Rate limit", f"{args.rate:g} req/s")
    info.add_row("Retries", str(args.retry))
    console.print(Panel(info, title="Configuration", border_style="green"))

    matched_links: list[str] = []

    def on_done(result) -> None:
        links = host_to_links[result.host]
        if result.matched:
            matched_links.extend(links)
            stats.matched_configs += len(links)
            stats.matched_hosts.append(
                f"{emoji_for(get_protocol(links[0]))} {result.host[:40]}")
        else:
            stats.failed_configs += len(links)

    checker = IranChecker(
        concurrency=args.threads,
        retries=args.retry,
        rate=args.rate,
        geoip_fallback=not args.no_geoip,
        stats=stats,
        on_done=on_done,
    )
    stats.start_time = time.time()
    task = asyncio.create_task(checker.check_hosts(hosts))
    try:
        with Live(iran_dashboard(stats), console=console, refresh_per_second=4) as live:
            while not task.done():
                live.update(iran_dashboard(stats))
                await asyncio.wait({task}, timeout=0.25)
            live.update(iran_dashboard(stats))
        task.result()
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    final = Table(title="Final Report", expand=True)
    final.add_column("Metric", style="cyan")
    final.add_column("Value", style="white")
    final.add_row("Unique hosts checked", str(stats.total_hosts))
    final.add_row("Total configs processed", str(stats.total_configs))
    final.add_row("Matched configs (Iran)",
                  f"[green]{len(matched_links)}[/green]")
    final.add_row("Not matched", f"[red]{stats.failed_configs}[/red]")
    final.add_row("Invalid configs",
                  f"[yellow]{stats.invalid_configs}[/yellow]")
    final.add_row(
        "API errors", f"[bold yellow]{stats.api_errors}[/bold yellow]")
    final.add_row("Time taken", stats.elapsed())
    final.add_row("Avg speed", stats.speed())
    console.print(final)

    if matched_links:
        matched_links = sorted(
            matched_links, key=lambda x: PROTOCOL_ORDER.get(get_protocol(x), 99))
        write_lines(args.out, matched_links)
        console.print(
            f"\n[green]Saved {len(matched_links)} matched configs →[/green] [cyan]{args.out}[/cyan]")
    else:
        console.print("\n[yellow]No Iran-registered hosts found[/yellow]")
    console.print("\n[bold green]Scan completed![/bold green]")
    return 0, matched_links


async def run_iran_checker(args: argparse.Namespace) -> int:
    code, _ = await iran_check(args)
    return code


# ─── delay ──────────────────────────────────────────────────────────────────

def delay_dashboard(stats: ScanStats) -> Table:
    table = Table(
        title=f"🚀 V2Scan Delay Checker • {datetime.now().strftime('%H:%M:%S')}",
        expand=True,
        show_edge=False,
    )
    table.add_column("Metric", style="cyan", width=24)
    table.add_column("Value", style="white")
    pct = stats.progress
    bar = "█" * int(pct / 2.5) + "░" * (40 - int(pct / 2.5))
    table.add_row("Progress", f"{bar} {pct:.1f}%")
    table.add_row(
        "Status", f"{stats.done}/{stats.total} checked | Testing: {stats.testing}/{stats.parallel}")
    table.add_row("Speed", f"{stats.speed:.1f}/s")
    table.add_row("Elapsed", format_time(stats.elapsed))
    table.add_row("ETA", stats.eta_text())
    table.add_row("", "")
    table.add_row(
        "✅ Alive", f"[green]{stats.alive}[/green] ({stats.alive / max(stats.done, 1) * 100:.1f}%)")
    table.add_row("❌ Dead", f"[red]{stats.dead}[/red]")
    if stats.delays:
        table.add_row("", "")
        table.add_row("Delay Stats", "")
        table.add_row("  Min", f"[cyan]{min(stats.delays)}ms[/cyan]")
        table.add_row(
            "  Avg", f"[cyan]{sum(stats.delays) / len(stats.delays):.0f}ms[/cyan]")
        table.add_row("  Max", f"[cyan]{max(stats.delays)}ms[/cyan]")
    if stats.recent:
        table.add_row("", "")
        lines = []
        for r in stats.recent:
            if r.alive:
                lines.append(
                    f"[green]✅ {emoji_for(r.protocol)} {r.delay:4d}ms[/green]")
            else:
                lines.append(
                    f"[red]❌ {emoji_for(r.protocol)} {r.error or 'Failed/Timeout'}[/red]")
        table.add_row("Recent Results", "\n".join(lines))
    return table


async def latency_test(links: list[str], info: SingBoxInfo, args: argparse.Namespace) -> list[TestResult]:
    """Run the batch tester under a live dashboard; returns all results."""
    stats = ScanStats(len(links), args.parallel)
    stats.start()
    tester = LatencyTester(
        info,
        probe=args.probe,
        timeout=args.timeout,
        startup_wait=args.startup_wait,
        parallel=args.parallel,
        batch_size=getattr(args, "batch_size", DEFAULT_BATCH_SIZE),
        on_start=stats.mark_testing,
        on_result=stats.record,
    )
    task = asyncio.create_task(tester.run(links))
    try:
        with Live(delay_dashboard(stats), console=console, refresh_per_second=5) as live:
            while not task.done():
                live.update(delay_dashboard(stats))
                await asyncio.wait({task}, timeout=0.2)
            live.update(delay_dashboard(stats))
        results = task.result()
    finally:
        if not task.done():  # Ctrl+C: stop probing and let LatencyTester clean up sing-box
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    return results


def report_latency(results: list[TestResult], stats_elapsed: float, out: str) -> None:
    live = sorted((r for r in results if r.alive), key=lambda r: r.delay)
    write_lines(out, [r.config for r in live])
    delays = [r.delay for r in live]

    console.print("\n[bold]✨ FINAL REPORT ✨[/bold]")
    console.print(
        f"Total tested: {len(results)} | Live: [green]{len(live)}[/green] | "
        f"Dead: [red]{len(results) - len(live)}[/red]"
    )
    console.print(
        f"Time: {format_time(stats_elapsed)} | Speed: {len(results) / max(stats_elapsed, 0.001):.1f}/s")
    if delays:
        console.print(
            f"Delays → Min: {min(delays)}ms | Avg: {sum(delays) / len(delays):.0f}ms | Max: {max(delays)}ms"
        )
        console.print(f"[green]💾 Saved {len(live)} configs → {out}[/green]")
        console.print("\n[bold]Top 3 fastest:[/bold]")
        for i, r in enumerate(live[:3], 1):
            console.print(f"   {i}. {emoji_for(r.protocol)} {r.delay}ms")
    else:
        console.print("[yellow]⚠️ No live configs[/yellow]")


async def delay_check(links: list[str], args: argparse.Namespace) -> int:
    """Delay-test ``links`` and write ``args.out``."""
    info = await require_singbox(args.singbox)
    if info is None:
        return 1
    counts = protocol_counts(links)
    console.print(
        Panel("[bold cyan]V2Scan Delay Checker[/bold cyan]", border_style="blue"))
    console.print(
        f"📊 Total: {len(links)} | sing-box {'.'.join(map(str, info.version or ()))} | {info.path}")
    console.print(f"   {protocol_line(counts)}")
    console.print(f"⚡ Parallel: {args.parallel} | 🌐 Probe: {args.probe}\n")

    started = time.time()
    results = await latency_test(links, info, args)
    report_latency(results, time.time() - started, args.out)
    return 0


async def run_delay_checker(args: argparse.Namespace) -> int:
    try:
        links = read_proxy_links(args.input)
    except FileNotFoundError:
        console.print(f"[red]File not found: {args.input}[/red]")
        return 1
    if not links:
        console.print("[red]❌ No valid proxy links found[/red]")
        return 1
    return await delay_check(links, args)


# ─── scan / pipeline / web ──────────────────────────────────────────────────

async def run_scan(args: argparse.Namespace) -> int:
    """Fetch configs from GitHub, deduplicate, then delay-test them."""
    console.print(Panel(
        "[bold cyan]Full Scan: Fetch → Dedup → Delay Test[/bold cyan]", border_style="blue"))

    console.print("\n[bold]Step 1/2: Fetching configs from GitHub...[/bold]")
    fetched = await fetch_sources(GITHUB_CONFIG_SOURCES, timeout=args.timeout)
    all_links = list(fetched.links)

    if args.input and os.path.exists(args.input):
        local = read_proxy_links(args.input)
        if local:
            all_links.extend(local)
            console.print(f"   Merged {len(local)} configs from {args.input}")

    if not all_links:
        console.print("[red]No configs fetched from any source[/red]")
        return 1

    unique, dup_count = dedup_links(all_links)
    console.print(
        f"   Total fetched: {len(all_links)} | Unique: {len(unique)} | Duplicates: {dup_count}")
    console.print(f"   {protocol_line(protocol_counts(unique))}")
    if fetched.errors:
        console.print(
            f"   [yellow]Source warnings: {len(fetched.errors)}[/yellow]")

    unique = sort_links(unique)
    write_lines(args.fetch_out, unique)
    console.print(f"   Saved all unique → [cyan]{args.fetch_out}[/cyan]")

    if await ensure_singbox(args.singbox) is None:
        console.print(f"[red]❌ sing-box not found: {args.singbox}[/red]")
        console.print(
            "[yellow]Configs were fetched but delay test skipped.[/yellow]")
        return 1

    console.print(
        f"\n[bold]Step 2/2: Delay testing {len(unique)} configs...[/bold]")
    return await delay_check(unique, args)


async def run_pipeline(args: argparse.Namespace) -> int:
    console.print(Panel(
        "[bold cyan]Pipeline: Iran Check → Delay Test[/bold cyan]", border_style="blue"))
    if await ensure_singbox(args.singbox) is None:
        console.print(f"[red]❌ sing-box not found: {args.singbox}[/red]")
        return 1

    iran_args = argparse.Namespace(
        input=args.input, threads=args.threads, out=args.iran_out, keep_duplicates=args.keep_duplicates,
        retry=args.retry, rate=args.rate, no_geoip=args.no_geoip,
    )
    console.print("\n[bold]Step 1/2: Iran host check[/bold]")
    code, matched = await iran_check(iran_args)
    if code != 0:
        return code
    if not matched:
        console.print(
            "[yellow]Pipeline stopped: no matched configs from Iran check[/yellow]")
        return 0

    console.print("\n[bold]Step 2/2: Delay test on matched configs[/bold]")
    return await delay_check(matched, args)


def run_web_ui(args: argparse.Namespace) -> int:
    ensure_deps(WEB_REQUIREMENTS)
    from .web.server import run_server

    console.print(
        Panel("[bold cyan]V2Scan — Web Dashboard[/bold cyan]", border_style="blue"))
    console.print(f"  Server: [cyan]http://{args.host}:{args.port}[/cyan]")
    console.print("  Press Ctrl+C to stop.\n")
    run_server(args.host, args.port)
    return 0


# ─── argument parsing & entry point ─────────────────────────────────────────

def _add_latency_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--singbox", default=DEFAULT_SINGBOX,
                   help="sing-box binary path")
    p.add_argument("--parallel", type=int, default=DEFAULT_PARALLEL,
                   help="Concurrent probes (default: 3)")
    p.add_argument("--timeout", type=int,
                   default=DEFAULT_TIMEOUT, help="Timeout in seconds")
    p.add_argument("--startup-wait", type=float, default=DEFAULT_STARTUP_WAIT,
                   help="Max seconds to wait for sing-box to become ready (polled, returns early)")
    p.add_argument("--probe", default=DEFAULT_PROBE, help="Probe URL")
    p.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                   help="Configs tested per sing-box process (default: 40)")


def _add_iran_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--threads", type=int, default=100,
                   help="Concurrent requests (default: 100)")
    p.add_argument("--retry", type=int, default=3,
                   help="Retry attempts per host (default: 3)")
    p.add_argument("--rate", type=float, default=50.0,
                   help="Max API requests per second (default: 50)")
    p.add_argument("--no-geoip", action="store_true",
                   help="Disable GeoIP fallback when the API fails")
    p.add_argument("--keep-duplicates", action="store_true",
                   help="Keep duplicate configs")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="v2scan",
        description="V2Scan — V2Ray config fetcher, deduplicator and latency tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    iran = sub.add_parser("iran", help="Check hosts against linkirani.ir API")
    iran.add_argument("-i", "--input", required=True,
                      help="Input file with proxy links")
    iran.add_argument("--out", default="iran_registered.txt",
                      help="Output file")
    _add_iran_args(iran)

    fetch = sub.add_parser(
        "fetch", help="Fetch free public V2Ray configs from GitHub")
    fetch.add_argument("--out", default="fetched_public.txt",
                       help="Output file (default: fetched_public.txt)")
    fetch.add_argument("--sources", nargs="*",
                       help="Custom raw URLs (overrides built-in list)")
    fetch.add_argument("--timeout", type=int, default=20,
                       help="HTTP timeout per source in seconds")

    scan = sub.add_parser(
        "scan", help="Fetch from GitHub + deduplicate + delay-test (all-in-one)")
    scan.add_argument("-i", "--input", default=None,
                      help="Optional local file to merge with fetched configs")
    scan.add_argument("--fetch-out", default="fetched_public.txt",
                      help="Output for all fetched configs")
    scan.add_argument("--out", default="live_with_delay.txt",
                      help="Output for live configs")
    _add_latency_args(scan)

    delay = sub.add_parser(
        "delay", help="Test config latency with sing-box (CLI)")
    delay.add_argument("-i", "--input", required=True, help="Configs file")
    delay.add_argument(
        "--out", default="live_with_delay.txt", help="Output file")
    _add_latency_args(delay)

    web = sub.add_parser("web", help="Start the V2Scan web dashboard")
    web.add_argument("--host", default="127.0.0.1",
                     help="Bind host (default: 127.0.0.1)")
    web.add_argument("--port", type=int, default=8686,
                     help="Port (default: 8686)")

    pipe = sub.add_parser(
        "pipeline", help="Iran check then delay test matched configs")
    pipe.add_argument("-i", "--input", required=True,
                      help="Input file with proxy links")
    pipe.add_argument("--iran-out", default="iran_registered.txt",
                      help="Intermediate Iran output")
    pipe.add_argument("--out", default="live_with_delay.txt",
                      help="Final delay output")
    _add_iran_args(pipe)
    _add_latency_args(pipe)
    return parser


async def async_main(args: argparse.Namespace) -> int:
    handlers = {
        "fetch": run_fetch,
        "scan": run_scan,
        "iran": run_iran_checker,
        "delay": run_delay_checker,
        "pipeline": run_pipeline,
    }
    handler = handlers.get(args.command)
    if handler is None:
        console.print(f"[red]Unknown command: {args.command}[/red]")
        return 1
    return await handler(args)


def main(argv: list[str] | None = None) -> int:
    # emoji output must not crash on cp1252 consoles/pipes
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        if args.command == "web":
            return run_web_ui(args)
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")
        return 130
    except Exception as exc:
        console.print(f"\n[red]Error: {exc}[/red]")
        return 1
    finally:
        kill_all()


if __name__ == "__main__":
    sys.exit(main())
