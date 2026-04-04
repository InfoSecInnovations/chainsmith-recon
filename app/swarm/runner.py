"""
app/swarm/runner.py - SwarmRunner: drop-in replacement for CheckLauncher.

When swarm mode is enabled, run_scan() uses SwarmRunner instead of
CheckLauncher. SwarmRunner does not execute checks itself -- it waits
for remote agents to complete tasks via the coordinator.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.swarm.coordinator import SwarmCoordinator

logger = logging.getLogger(__name__)

POLL_INTERVAL = 0.5  # seconds between completion checks


class SwarmRunner:
    """
    Waits for swarm agents to complete all tasks.

    Exposes the same interface as CheckLauncher so the scan route
    (state.runner.checks) works without modification.
    """

    def __init__(self, checks: list, context: dict, coordinator: SwarmCoordinator):
        # Expose checks as a dict keyed by name (for route compatibility)
        self.checks = {c.name: c for c in checks}
        self.context = context
        self.coordinator = coordinator

    async def run_all(
        self,
        on_check_start: Callable | None = None,
        on_check_complete: Callable | None = None,
    ) -> list:
        """
        Block until all coordinator tasks are terminal.

        Progress callbacks are forwarded to the coordinator so they
        fire when agents report results via the API.
        """
        self.coordinator._on_check_start = on_check_start
        self.coordinator._on_check_complete = on_check_complete

        logger.info("SwarmRunner waiting for %d tasks to complete...", len(self.coordinator.tasks))

        while self.coordinator.is_running:
            await asyncio.sleep(POLL_INTERVAL)

        logger.info("SwarmRunner done: %d findings", len(self.coordinator.findings))
        return self.coordinator.findings
