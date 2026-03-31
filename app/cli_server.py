"""
app/cli_server.py - Server lifecycle management for CLI

Ensures a Chainsmith API server is running before CLI commands execute.
If no server is reachable, auto-starts uvicorn as a background subprocess.
"""

import atexit
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx


PID_DIR = Path.home() / ".chainsmith"
PID_FILE = PID_DIR / "server.pid"


class ServerManager:
    """Manage the Chainsmith API server for CLI use."""

    def __init__(self):
        self._process = None

    def ensure_server(self, host: str = "127.0.0.1", port: int = 8000) -> str:
        """Return base_url of a healthy server, starting one if needed."""
        base_url = f"http://{host}:{port}"

        if self._is_healthy(base_url):
            return base_url

        self._start(host, port)
        return base_url

    def shutdown(self):
        """Terminate the managed subprocess if we started one."""
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._cleanup_pid()

    # ─── Internal ─────────────────────────────────────────────

    def _is_healthy(self, base_url: str) -> bool:
        try:
            resp = httpx.get(f"{base_url}/health", timeout=2.0)
            return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException, OSError):
            return False

    def _start(self, host: str, port: int):
        PID_DIR.mkdir(parents=True, exist_ok=True)

        self._process = subprocess.Popen(
            [
                sys.executable, "-m", "uvicorn",
                "app.main:app",
                "--host", host,
                "--port", str(port),
                "--log-level", "warning",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        PID_FILE.write_text(str(self._process.pid))
        atexit.register(self.shutdown)

        base_url = f"http://{host}:{port}"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise RuntimeError(
                    f"Server process exited with code {self._process.returncode}. "
                    "Try running 'chainsmith serve' to see errors."
                )
            if self._is_healthy(base_url):
                return
            time.sleep(0.3)

        self._process.terminate()
        raise RuntimeError(
            "Server did not become healthy within 10 seconds. "
            "Try running 'chainsmith serve' to diagnose."
        )

    def _cleanup_pid(self):
        try:
            PID_FILE.unlink(missing_ok=True)
        except OSError:
            pass
