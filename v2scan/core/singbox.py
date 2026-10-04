"""sing-box discovery, config generation and process management."""

from __future__ import annotations

import asyncio
import atexit
import copy
import json
import os
import re
import shutil
import socket
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import DEFAULT_SINGBOX, PROJECT_DIR

Version = tuple[int, int, int]

# First sing-box release with the new-style DNS servers and `default_domain_resolver`.
MODERN_CONFIG_VERSION: Version = (1, 12, 0)
_CREATE_NO_WINDOW = 0x08000000


class SingBoxError(RuntimeError):
    """sing-box is missing or failed to start."""

    def __init__(self, message: str, log: str = "") -> None:
        super().__init__(message)
        self.log = log


@dataclass(slots=True)
class SingBoxInfo:
    path: str
    version: Version | None

    @property
    def modern(self) -> bool:
        """Unknown versions are assumed modern (the bundled release is 1.14)."""
        return self.version is None or self.version >= MODERN_CONFIG_VERSION


# ─── Discovery ──────────────────────────────────────────────────────────────

def locate_singbox(path: str = DEFAULT_SINGBOX) -> str | None:
    """Resolve the sing-box binary: explicit path, PATH, then a copy bundled in the project dir."""
    found = shutil.which(path)
    if found:
        return found
    if Path(path).is_file():
        return str(Path(path).resolve())
    if path == DEFAULT_SINGBOX:
        name = "sing-box.exe" if sys.platform == "win32" else "sing-box"
        for candidate in sorted(PROJECT_DIR.glob(f"sing-box*/**/{name}")):
            if candidate.is_file():
                return str(candidate)
    return None


def _parse_version(text: str) -> Version | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


async def ensure_singbox(path: str = DEFAULT_SINGBOX) -> SingBoxInfo | None:
    """Return binary info if sing-box runs, else ``None``."""
    resolved = locate_singbox(path)
    if not resolved:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            resolved, "version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL,
            creationflags=_CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
    except (OSError, asyncio.TimeoutError):
        return None
    if proc.returncode != 0:
        return None
    return SingBoxInfo(resolved, _parse_version(out.decode(errors="ignore")))


# ─── Config generation ──────────────────────────────────────────────────────

def allocate_ports(count: int) -> list[int]:
    """Reserve ``count`` distinct free loopback ports (all held open until every one is chosen)."""
    socks: list[socket.socket] = []
    try:
        for _ in range(count):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def build_batch_config(
    outbounds: list[dict[str, Any]], ports: list[int], *, modern: bool = True
) -> dict[str, Any]:
    """One sing-box config exposing ``outbounds[i]`` on its own SOCKS port ``ports[i]``.

    Tags are ``in-<i>`` / ``out-<i>``; a route rule pins each inbound to its outbound.
    """
    if len(outbounds) != len(ports):
        raise ValueError("outbounds and ports must have the same length")

    inbounds: list[dict[str, Any]] = []
    out_list: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    for i, (outbound, port) in enumerate(zip(outbounds, ports)):
        ob = copy.deepcopy(outbound)
        ob["tag"] = f"out-{i}"
        out_list.append(ob)
        inbounds.append({
            "type": "socks",
            "tag": f"in-{i}",
            "listen": "127.0.0.1",
            "listen_port": port,
        })
        rule: dict[str, Any] = {"inbound": [f"in-{i}"], "outbound": f"out-{i}"}
        if modern:
            rule["action"] = "route"
        rules.append(rule)
    out_list.append({"type": "direct", "tag": "direct"})

    config: dict[str, Any] = {
        "log": {"level": "error", "timestamp": False},
        "inbounds": inbounds,
        "outbounds": out_list,
        "route": {"rules": rules},
    }
    if modern:
        config["dns"] = {"servers": [
            {"type": "udp", "tag": "dns-direct", "server": "8.8.8.8"}]}
        config["route"]["default_domain_resolver"] = "dns-direct"
    else:
        config["dns"] = {"servers": [
            {"tag": "dns-direct", "address": "8.8.8.8"}]}
    return config


_TAG_RE = re.compile(r"\bout-(\d+)\b")
_INDEX_RE = re.compile(r"outbound\[(\d+)\]")


def find_failed_outbound(log: str, count: int) -> int | None:
    """Extract the index of the outbound sing-box rejected from its error log, if identifiable."""
    for regex in (_TAG_RE, _INDEX_RE):
        match = regex.search(log)
        if match and int(match[1]) < count:
            return int(match[1])
    return None


# ─── Process management ─────────────────────────────────────────────────────

_ACTIVE: set["SingBoxProcess"] = set()
_job_handle: Any = None


def _bind_to_kill_job(pid: int) -> None:
    """Windows: make the OS kill ``pid`` when this Python process dies (even on a hard kill)."""
    global _job_handle
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    class _Basic(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit",
             ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize",
             ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _Extended(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _Basic), ("IoInfo", ctypes.c_uint64 * 6),
            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed",
             ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    if _job_handle is None:
        job = k32.CreateJobObjectW(None, None)
        info = _Extended()
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        info.BasicLimitInformation.LimitFlags = 0x2000
        if not job or not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            return
        _job_handle = job
    # PROCESS_SET_QUOTA | PROCESS_TERMINATE
    handle = k32.OpenProcess(0x0101, False, pid)
    if handle:
        k32.AssignProcessToJobObject(_job_handle, handle)
        k32.CloseHandle(handle)


class SingBoxProcess:
    """A sing-box instance running one generated config from a private temp directory."""

    def __init__(self, binary: str, config: dict[str, Any], ports: list[int]) -> None:
        self.binary = binary
        self.config = config
        self.ports = ports
        self._tmpdir: str | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._log_path = ""

    async def __aenter__(self) -> "SingBoxProcess":
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()

    def read_log(self) -> str:
        try:
            return Path(self._log_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    async def start(self, ready_timeout: float = 10.0) -> None:
        """Launch sing-box and wait until every SOCKS inbound accepts connections."""
        self._tmpdir = tempfile.mkdtemp(prefix="v2scan_")
        cfg_path = os.path.join(self._tmpdir, "config.json")
        self._log_path = os.path.join(self._tmpdir, "sing-box.log")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(self.config, f)

        _ACTIVE.add(self)
        try:
            with open(self._log_path, "wb") as log_fh:
                self._proc = await asyncio.create_subprocess_exec(
                    self.binary, "run", "-c", cfg_path, "--disable-color",
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=log_fh,
                    stderr=asyncio.subprocess.STDOUT,
                    creationflags=_CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                )
            try:
                _bind_to_kill_job(self._proc.pid)
            except Exception:  # best-effort safety net; normal cleanup still applies
                pass
            await self._wait_ready(ready_timeout)
        except BaseException:
            await self.stop()
            raise

    async def _wait_ready(self, timeout: float) -> None:
        """Wait until all inbounds accept connections, failing fast if sing-box exits."""
        assert self._proc is not None
        exited = asyncio.ensure_future(self._proc.wait())
        ready = asyncio.ensure_future(self._poll_ports(self.ports))
        try:
            done, _ = await asyncio.wait(
                {exited, ready}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
            )
            if ready in done:
                return
            if exited in done:
                raise SingBoxError(
                    f"sing-box exited with code {self._proc.returncode}", self.read_log())
            raise SingBoxError(
                "sing-box did not become ready in time", self.read_log())
        finally:
            for task in (exited, ready):
                task.cancel()
            await asyncio.gather(exited, ready, return_exceptions=True)

    @staticmethod
    async def _poll_ports(ports: list[int]) -> None:
        async def is_open(port: int) -> bool:
            try:  # a refused connect can take ~1s on Windows, so probe ports concurrently
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port), timeout=1
                )
            except (OSError, asyncio.TimeoutError):
                return False
            writer.close()
            return True

        pending = list(ports)
        while pending:
            opened = await asyncio.gather(*(is_open(p) for p in pending))
            pending = [p for p, ok in zip(pending, opened) if not ok]
            if pending:
                await asyncio.sleep(0.1)

    async def stop(self) -> None:
        """Terminate the process and delete its temp directory (idempotent)."""
        proc, self._proc = self._proc, None
        if proc is not None and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=3)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=3)
                except (ProcessLookupError, asyncio.TimeoutError):
                    pass
        self._cleanup_dir()
        _ACTIVE.discard(self)

    def _cleanup_dir(self) -> None:
        if self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    def kill_now(self) -> None:
        """Synchronous best-effort cleanup (used from ``atexit``)."""
        proc = self._proc
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
        self._cleanup_dir()


def kill_all() -> None:
    """Kill every running sing-box instance and remove their temp directories."""
    for proc in list(_ACTIVE):
        proc.kill_now()
    _ACTIVE.clear()


atexit.register(kill_all)
