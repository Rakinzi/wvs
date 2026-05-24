"""
Start Flask + Celery worker + Celery beat in one command.
Usage:  uv run python start.py
        PORT=5001 uv run python start.py
Stop:   Ctrl+C
"""
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

COLORS = {
    "FLASK": "\033[94m",
    "WORKER": "\033[92m",
    "BEAT": "\033[93m",
    "ZAP": "\033[95m",
    "RESET": "\033[0m",
}


def detect_zap_command():
    explicit = os.getenv("ZAP_START_CMD", "").strip()
    if explicit:
        return shlex.split(explicit)

    candidates = [
        Path("/Applications/OWASP ZAP.app/Contents/MacOS/OWASP ZAP"),
        Path("/Applications/ZAP.app/Contents/MacOS/OWASP ZAP"),
        Path("/opt/homebrew/bin/zap.sh"),
        Path("/usr/local/bin/zap.sh"),
        Path("/usr/bin/zap.sh"),
    ]

    for candidate in candidates:
        if candidate.exists():
            return [str(candidate)]

    return None


def build_procs():
    procs = {
        "FLASK": ["python", "wsgi.py"],
        "WORKER": ["celery", "-A", "app.celery_app", "worker", "--loglevel=warning", "--concurrency=2"],
        "BEAT": ["celery", "-A", "app.celery_app", "beat", "--loglevel=warning"],
    }

    if ZAP_AUTO_START:
        zap_cmd = detect_zap_command()
        if zap_cmd:
            procs["ZAP"] = zap_cmd
        else:
            print("\033[93m[ZAP]\033[0m auto-start requested, but no ZAP executable was found. "
                  "Set ZAP_START_CMD to your local launch command.")

    return procs


PROCS = build_procs()


def stream(name, proc):
    color = COLORS.get(name, "")
    reset = COLORS["RESET"]
    for line in proc.stdout:
        sys.stdout.write(f"{color}[{name}]{reset} {line}")
        sys.stdout.flush()


env = {**os.environ, "PORT": PORT}
procs = {}

print(f"\033[1mStarting WVS stack on port {PORT}…\033[0m")

for name, cmd in PROCS.items():
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1, env=env)
    procs[name] = p
    threading.Thread(target=stream, args=(name, p), daemon=True).start()
    print(f"  {COLORS[name]}[{name}]{COLORS['RESET']} started (pid {p.pid})")
    time.sleep(0.5)


def shutdown(*_):
    print("\n\033[1mShutting down…\033[0m")
    for name, p in procs.items():
        try:
            p.terminate()
        except Exception:
            pass
    for name, p in procs.items():
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
    sys.exit(0)


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

while True:
    for name, p in procs.items():
        if p.poll() is not None:
            print(f"\033[91m[{name}] exited unexpectedly (code {p.returncode}) — restarting…\033[0m")
            cmd = PROCS[name]
            new_p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1, env=env)
            procs[name] = new_p
            threading.Thread(target=stream, args=(name, new_p), daemon=True).start()
    time.sleep(2)
