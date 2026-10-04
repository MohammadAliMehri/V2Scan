"""Constants, defaults and small shared helpers."""

from __future__ import annotations

import random
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = PACKAGE_DIR.parent

# Canonical protocol names -> URL schemes accepted for that protocol.
PROTOCOL_SCHEMES: dict[str, tuple[str, ...]] = {
    "vless": ("vless",),
    "vmess": ("vmess",),
    "trojan": ("trojan",),
    "ss": ("ss",),
    "hysteria2": ("hysteria2", "hy2"),
}
ALL_PREFIXES: tuple[str, ...] = tuple(
    f"{scheme}://" for schemes in PROTOCOL_SCHEMES.values() for scheme in schemes
)

PROTOCOL_ORDER: dict[str, int] = {
    "vless": 0, "vmess": 1, "trojan": 2, "ss": 3, "hysteria2": 4}
PROTOCOL_EMOJI: dict[str, str] = {
    "vless": "🟦",
    "vmess": "🟪",
    "trojan": "🟧",
    "ss": "🟩",
    "hysteria2": "🟥",
}

IRAN_API_URL = "https://api.linkirani.ir/shortlink"
DEFAULT_PROBE = "https://www.google.com/generate_204"
DEFAULT_SINGBOX = "sing-box"

# Defaults shared by the CLI and the web API (match the legacy script).
DEFAULT_PARALLEL = 3
DEFAULT_TIMEOUT = 15
DEFAULT_STARTUP_WAIT = 2.0
DEFAULT_BATCH_SIZE = 40
MAX_WORKERS = 8

# Well-known GitHub repos that publish free V2Ray/proxy configs: (raw url, description)
GITHUB_CONFIG_SOURCES: list[tuple[str, str]] = [
    ("https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
     "barry-far/V2ray-config (aggregated subs)"),
    ("https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
     "mfuu/v2ray (daily updated)"),
    ("https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
     "peasoft/NoMoreWalls (aggregated)"),
    ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
     "mahdibland/V2RayAggregator"),
    ("https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
     "Epodonios/v2ray-configs"),
    ("https://raw.githubusercontent.com/freefq/free/master/v2",
     "freefq/free (free servers)"),
    ("https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
     "Pawdroid/Free-servers"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0) Edge/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/605.1.15",
    "Mozilla/5.0 (Android 14; Mobile) Chrome/120.0.0.0 Mobile Safari/537.37",
]


def random_user_agent() -> str:
    """Return a random browser User-Agent string."""
    return random.choice(USER_AGENTS)


def format_time(seconds: float) -> str:
    """Format a duration as ``12s``, ``3m 4s`` or ``1h 5m``."""
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"
