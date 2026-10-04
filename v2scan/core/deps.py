"""Runtime dependency bootstrap (keeps the legacy "auto-install" behaviour)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys

# pip requirement -> modules that must be importable for it to count as installed
CORE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "rich": ("rich",),
    "httpx[socks,http2]": ("httpx", "socksio", "h2"),
}
WEB_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "fastapi": ("fastapi",),
    "uvicorn": ("uvicorn",),
    "qrcode": ("qrcode",),
}


def ensure_deps(requirements: dict[str, tuple[str, ...]]) -> None:
    """Install any requirement whose modules are missing via pip."""
    missing = [
        req for req, modules in requirements.items()
        if any(importlib.util.find_spec(m) is None for m in modules)
    ]
    if not missing:
        return
    print(f"Installing: {', '.join(missing)}", file=sys.stderr)
    subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
