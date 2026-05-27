"""
Start Flask + Celery workers + Celery beat in one command.

Usage:
    uv run python start.py
    PORT=5001 uv run python start.py
    ZAP_ENABLED=true ZAP_AUTO_START=true ZAP_START_CMD="/Applications/ZAP.app/Contents/MacOS/ZAP.sh" uv run python start.py

Stop:
    Ctrl+C
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


PORT = os.getenv("PORT", "5001")
ZAP_ENABLED = os.getenv("ZAP_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}
ZAP_AUTO_START = os.getenv("ZAP_AUTO_START", "").strip().lower() in {"1", "true", "yes", "on"} or ZAP_ENABLED
ZAP_BASE_URL = os.getenv("ZAP_BASE_URL", "http://127.0.0.1:8080").strip()
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "").strip()

SECURITY_SCAN_QUEUE = os.getenv("SECURITY_SCAN_QUEUE", "security_scans").strip()
UX_SCAN_QUEUE = os.getenv("UX_SCAN_QUEUE", "ux_scans").strip()
SECURITY_WORKER_CONCURRENCY = os.getenv("SECURITY_WORKER_CONCURRENCY", "2").strip()
UX_WORKER_CONCURRENCY = os.getenv("UX_WORKER_CONCURRENCY", "1").strip()
START_BEAT = os.getenv("START_CELERY_BEAT", "true").strip().lower() in {"1", "true", "yes", "on"}

COLORS = {
    "FLASK": "\033[94m",
    "SECURITY_WORKER": "\033[92m",
    "UX_WORKER": "\033[96m",
    "BEAT": "\033[93m",
    "ZAP": "\033[95m",
    "RESET": "\033[0m",
}


def _python_module_cmd(*args: str) -> list[str]:
    return [sys.executable, "-m", *args]


def _zap_host_port() -> tuple[str, str]:
    from urllib.parse import urlparse

    parsed = urlparse(ZAP_BASE_URL)
    return parsed.hostname or "127.0.0.1", str(parsed.port or 8080)


def detect_zap_command() -> list[str] | None:
    explicit = os.getenv("ZAP_START_CMD", "").strip()
    if explicit:
        parts = shlex.split(explicit)
    else:
        candidates = [
            Path("/Applications/OWASP ZAP.app/Contents/MacOS/OWASP ZAP"),
            Path("/Applications/ZAP.app/Contents/MacOS/OWASP ZAP"),
            Path("/Applications/ZAP.app/Contents/MacOS/ZAP.sh"),
            Path("/opt/homebrew/bin/zap.sh"),
            Path("/usr/local/bin/zap.sh"),
            Path("/usr/bin/zap.sh"),
        ]
        parts = None
        for candidate in candidates:
            if candidate.exists():
                parts = [str(candidate)]
                break

    if not parts:
        return None

    lowered = " ".join(parts).lower()
    if "-daemon" in lowered:
        return parts

    host, port = _zap_host_port()
    daemonized = [*parts, "-daemon", "-host", host, "-port", port]
    if ZAP_API_KEY:
        daemonized.extend(["-config", f"api.key={ZAP_API_KEY}"])
    else:
        daemonized.extend(["-config", "api.disablekey=true"])
    return daemonized


def build_procs() -> dict[str, list[str]]:
    procs = {
        "FLASK": [sys.executable, "wsgi.py"],
        "SECURITY_WORKER": [
            * _python_module_cmd("celery"),
            "-A",
            "app.celery_app:celery_app",
            "worker",
            "-Q",
            SECURITY_SCAN_QUEUE,
            "--loglevel=warning",
            "--concurrency",
            SECURITY_WORKER_CONCURRENCY,
        ],
        "UX_WORKER": [
            * _python_module_cmd("celery"),
            "-A",
            "app.celery_app:celery_app",
            "worker",
            "-Q",
            UX_SCAN_QUEUE,
            "--loglevel=warning",
            "--concurrency",
            UX_WORKER_CONCURRENCY,
        ],
    }

    if START_BEAT:
        procs["BEAT"] = [
            * _python_module_cmd("celery"),
            "-A",
            "app.celery_app:celery_app",
            "beat",
            "--loglevel=warning",
        ]

    if ZAP_AUTO_START:
        zap_cmd = detect_zap_command()
        if zap_cmd:
            procs["ZAP"] = zap_cmd
        else:
            print(
                "\033[93m[ZAP]\033[0m auto-start requested, but no ZAP executable was found. "
                "Set ZAP_START_CMD to your local launch command."
            )

    return procs


PROCS = build_procs()


def stream(name: str, proc: subprocess.Popen[str]) -> None:
    color = COLORS.get(name, "")
    reset = COLORS["RESET"]
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(f"{color}[{name}]{reset} {line}")
        sys.stdout.flush()


env = {**os.environ, "PORT": PORT}
procs: dict[str, subprocess.Popen[str]] = {}

print(f"\033[1mStarting WVS stack on port {PORT}…\033[0m")
print(
    f"  Queues: security={SECURITY_SCAN_QUEUE} (concurrency={SECURITY_WORKER_CONCURRENCY}), "
    f"ux={UX_SCAN_QUEUE} (concurrency={UX_WORKER_CONCURRENCY})"
)
if ZAP_AUTO_START:
    print(f"  ZAP auto-start: enabled ({ZAP_BASE_URL})")


for name, cmd in PROCS.items():
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )
    procs[name] = proc
    threading.Thread(target=stream, args=(name, proc), daemon=True).start()
    print(f"  {COLORS[name]}[{name}]{COLORS['RESET']} started (pid {proc.pid})")
    time.sleep(0.5)


def shutdown(*_) -> None:
    print("\n\033[1mShutting down…\033[0m")
    for proc in procs.values():
        try:
            proc.terminate()
        except Exception:
            pass
    for proc in procs.values():
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    sys.exit(0)


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


while True:
    for name, proc in list(procs.items()):
        if proc.poll() is not None:
            print(f"\033[91m[{name}] exited unexpectedly (code {proc.returncode}) — restarting…\033[0m")
            replacement = subprocess.Popen(
                PROCS[name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
            procs[name] = replacement
            threading.Thread(target=stream, args=(name, replacement), daemon=True).start()
    time.sleep(2)
