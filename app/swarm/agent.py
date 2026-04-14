"""
app/swarm/agent.py - Swarm agent client.

Runs as a standalone process, connects to a coordinator, polls for
tasks, executes checks locally, and reports observations back.

Usage:
    agent = SwarmAgent(coordinator_url="http://10.0.0.1:8000", api_key="...", name="dmz-01")
    await agent.run()
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import socket
import time
from urllib.parse import urlparse

import httpx

from app.check_resolver import get_real_checks
from app.checks.base import Service
from app.lib.targets import host_matches_pattern

logger = logging.getLogger(__name__)

POLL_INTERVAL = 2.0  # seconds between task polls when idle
HEARTBEAT_INTERVAL = 30  # seconds between heartbeats


class SwarmAgent:
    """
    Lightweight swarm worker that polls a coordinator for tasks,
    executes checks locally, and reports results.
    """

    def __init__(
        self,
        coordinator_url: str,
        api_key: str,
        name: str = "",
        capabilities: list[str] | None = None,
        max_concurrent: int = 3,
    ):
        self.coordinator_url = coordinator_url.rstrip("/")
        self.api_key = api_key
        self.name = name or socket.gethostname()
        self.capabilities = capabilities or []
        self.max_concurrent = max_concurrent

        self.agent_id: str | None = None
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._running = False
        self._client: httpx.AsyncClient | None = None

        # Pre-load all check classes keyed by name
        self._checks_by_name = {c.name: c for c in get_real_checks()}

    # ── HTTP helpers ─────────────────────────────────────────────

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.coordinator_url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=30.0,
            )
        return self._client

    async def _post(self, path: str, json: dict | None = None) -> httpx.Response:
        return await self._get_client().post(path, json=json or {})

    async def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        return await self._get_client().get(path, params=params)

    async def _delete(self, path: str) -> httpx.Response:
        return await self._get_client().delete(path)

    # ── Lifecycle ────────────────────────────────────────────────

    async def register(self):
        """Register with the coordinator."""
        resp = await self._post(
            "/api/swarm/register",
            json={
                "name": self.name,
                "capabilities": self.capabilities,
                "max_concurrent": self.max_concurrent,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self.agent_id = data["agent_id"]
        logger.info("Registered as %s (id: %s)", self.name, self.agent_id)

    async def deregister(self):
        """Deregister from the coordinator."""
        if self.agent_id:
            try:
                await self._delete(f"/api/swarm/agents/{self.agent_id}")
                logger.info("Deregistered agent %s", self.agent_id)
            except Exception:
                logger.warning("Failed to deregister cleanly", exc_info=True)

    async def _heartbeat_loop(self):
        """Background heartbeat sender."""
        while self._running:
            try:
                await self._post("/api/swarm/heartbeat", json={"agent_id": self.agent_id})
            except Exception:
                logger.warning("Heartbeat failed", exc_info=True)
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    async def run(self):
        """Main agent loop: register, poll, execute, report."""
        await self.register()
        self._running = True

        # Handle graceful shutdown
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                # Windows doesn't support add_signal_handler
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self._shutdown()))

        heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        try:
            await self._poll_loop()
        finally:
            self._running = False
            heartbeat_task.cancel()
            await self.deregister()
            client = self._get_client()
            await client.aclose()

    async def _shutdown(self):
        """Signal handler for graceful shutdown."""
        logger.info("Shutting down agent...")
        self._running = False

    # ── Task polling ─────────────────────────────────────────────

    async def _poll_loop(self):
        """Poll for tasks and execute them."""
        consecutive_empty = 0

        while self._running:
            try:
                resp = await self._get(
                    "/api/swarm/tasks/next",
                    params={"agent_id": self.agent_id},
                )

                if resp.status_code == 204:
                    # Nothing available yet
                    consecutive_empty += 1
                    await asyncio.sleep(POLL_INTERVAL)
                    continue

                resp.raise_for_status()
                data = resp.json()

                # Check if coordinator signalled scan is done
                if data.get("done"):
                    logger.info("Coordinator reports scan complete. Exiting.")
                    break

                consecutive_empty = 0
                # Execute in background (respecting concurrency semaphore)
                asyncio.create_task(self._handle_task(data))

            except httpx.HTTPStatusError as e:
                logger.error("Poll error: %s", e)
                await asyncio.sleep(POLL_INTERVAL * 2)
            except Exception:
                logger.error("Unexpected poll error", exc_info=True)
                await asyncio.sleep(POLL_INTERVAL * 2)

    async def _handle_task(self, task_data: dict):
        """Execute a single task with concurrency control."""
        task_id = task_data["task_id"]
        check_name = task_data["check_name"]

        async with self._semaphore:
            # Acknowledge start
            try:
                await self._post(
                    f"/api/swarm/tasks/{task_id}/start",
                    json={
                        "agent_id": self.agent_id,
                    },
                )
            except Exception:
                logger.error("Failed to acknowledge task %s start", task_id, exc_info=True)
                return

            # Execute
            try:
                result = await self._execute_task(task_data)
                await self._post(
                    f"/api/swarm/tasks/{task_id}/result",
                    json={
                        "agent_id": self.agent_id,
                        "success": result["success"],
                        "observations": result["observations"],
                        "outputs": result["outputs"],
                        "services": result["services"],
                        "errors": result["errors"],
                        "duration_ms": result["duration_ms"],
                    },
                )
                logger.info(
                    "Task %s (%s) complete: %d observations",
                    task_id,
                    check_name,
                    len(result["observations"]),
                )
            except Exception as e:
                logger.error("Task %s (%s) failed: %s", task_id, check_name, e, exc_info=True)
                try:
                    await self._post(
                        f"/api/swarm/tasks/{task_id}/fail",
                        json={
                            "agent_id": self.agent_id,
                            "error": str(e),
                        },
                    )
                except Exception:
                    logger.error("Failed to report task failure", exc_info=True)

    # ── Check execution ──────────────────────────────────────────

    async def _execute_task(self, task_data: dict) -> dict:
        """
        Instantiate and run the check for this task.

        Returns a dict with: success, observations, outputs, services, errors, duration_ms
        """
        check_name = task_data["check_name"]
        check = self._checks_by_name.get(check_name)
        if check is None:
            raise ValueError(f"Unknown check: {check_name}")

        # Engagement-window gate — symmetric with coordinator-side Guardian.
        window_data = task_data.get("engagement_window")
        if window_data:
            from app.guardian import Guardian
            from app.proof_of_scope import EngagementWindow

            window = EngagementWindow(**window_data)
            target = task_data.get("target", {})
            local_guardian = Guardian.from_scope(
                target.get("url", ""), exclude=[], forbidden_techniques=[]
            )
            allowed, reason = local_guardian.check_engagement_window(
                window, acknowledged=bool(task_data.get("outside_window_acknowledged"))
            )
            if not allowed:
                raise RuntimeError(f"Swarm task blocked: {reason}")

        # Build context from upstream + target
        target = task_data.get("target", {})
        upstream = task_data.get("upstream_context", {})

        context = dict(upstream)
        context["base_domain"] = (
            target.get("url", "").replace("https://", "").replace("http://", "").rstrip("/")
        )
        context["scope_domains"] = target.get("domains", [])
        if "services" in upstream:
            context["services"] = [
                Service.from_dict(s) if isinstance(s, dict) else s for s in upstream["services"]
            ]
        if "services" not in context:
            context["services"] = []

        # Set up scope validator from task payload
        domains = target.get("domains", [])
        ports = target.get("ports", [])
        check.set_scope_validator(self._make_scope_validator(domains, ports))

        # Apply rate limit from coordinator
        rate_limit = task_data.get("rate_limit", 10.0)
        check.requests_per_second = rate_limit

        # Execute
        start = time.monotonic()
        result = await check.execute(context)
        duration_ms = int((time.monotonic() - start) * 1000)

        return {
            "success": result.success,
            "observations": [f.to_dict() for f in result.observations],
            "outputs": self._serialize_outputs(result.outputs),
            "services": [s.to_dict() for s in result.services],
            "errors": result.errors,
            "duration_ms": duration_ms,
        }

    @staticmethod
    def _make_scope_validator(domains: list[str], ports: list[int]):
        """Build a scope validator from task-payload domains and ports."""

        def validator(url: str) -> bool:
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                host_ok = any(host_matches_pattern(host, d) for d in domains) if domains else True
                port_ok = (not ports) or (port in ports)
                return host_ok and port_ok
            except Exception:
                return False

        return validator

    @staticmethod
    def _serialize_outputs(outputs: dict) -> dict:
        """Ensure all output values are JSON-serializable."""
        serialized = {}
        for key, value in outputs.items():
            if isinstance(value, list):
                serialized[key] = [
                    item.to_dict() if hasattr(item, "to_dict") else item for item in value
                ]
            elif hasattr(value, "to_dict"):
                serialized[key] = value.to_dict()
            else:
                serialized[key] = value
        return serialized
