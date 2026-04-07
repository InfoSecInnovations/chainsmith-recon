"""
app/swarm/coordinator.py - Swarm task scheduler and agent registry.

The coordinator decomposes a scan into tasks using ChainOrchestrator,
then assigns tasks to agents as they poll. Context (outputs, services,
observations) accumulates as tasks complete.

Singleton access: get_coordinator()
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from app.check_resolver import infer_suite
from app.checks.base import Service
from app.checks.chain import ChainOrchestrator
from app.config import get_config
from app.swarm.models import (
    AgentInfo,
    AgentStatus,
    CoordinatorStatus,
    SwarmTask,
    TaskResultPayload,
    TaskStatus,
)

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger(__name__)


class SwarmCoordinator:
    """
    Central coordinator for distributed scan execution.

    Lifecycle:
      1. create_tasks_from_plan() -- build task queue from checks
      2. Agents poll get_next_task() and call start_task / complete_task / fail_task
      3. When all tasks are terminal, scan is complete
    """

    def __init__(self):
        self.agents: dict[str, AgentInfo] = {}
        self.tasks: dict[str, SwarmTask] = {}
        self.phase_tasks: dict[int, list[str]] = {}  # phase_number -> [task_ids]
        self.scan_context: dict[str, Any] = {}
        self.observations: list[dict] = []
        self.state: AppState | None = None
        self.scan_id: str | None = None
        self.scan_start_time: float | None = None
        self.is_running: bool = False
        self.observation_writer: Any | None = None  # ObservationWriter, set by scanner

        # Progress callbacks (set by SwarmRunner)
        self._on_check_start: Callable | None = None
        self._on_check_complete: Callable | None = None

    def reset(self):
        """Clear all state for a new scan."""
        self.tasks.clear()
        self.phase_tasks.clear()
        self.scan_context.clear()
        self.observations.clear()
        self.state = None
        self.scan_id = None
        self.scan_start_time = None
        self.is_running = False
        self.observation_writer = None
        self._on_check_start = None
        self._on_check_complete = None

    # ── Agent management ─────────────────────────────────────────

    def register_agent(
        self,
        name: str,
        api_key_name: str,
        capabilities: list[str] | None = None,
        max_concurrent: int = 3,
    ) -> AgentInfo:
        """Register a new agent. Returns AgentInfo with assigned UUID."""
        cfg = get_config()
        if len(self.agents) >= cfg.swarm.max_agents:
            raise ValueError(f"Maximum agents ({cfg.swarm.max_agents}) reached")

        agent_id = str(uuid.uuid4())
        agent = AgentInfo(
            agent_id=agent_id,
            name=name or f"agent-{agent_id[:8]}",
            api_key_name=api_key_name,
            capabilities=capabilities or [],
            max_concurrent=max_concurrent,
        )
        self.agents[agent_id] = agent
        logger.info("Agent registered: %s (%s)", agent.name, agent_id)
        return agent

    def deregister_agent(self, agent_id: str) -> bool:
        """Remove an agent and re-queue its assigned tasks."""
        agent = self.agents.pop(agent_id, None)
        if agent is None:
            return False

        for task_id in list(agent.current_tasks):
            task = self.tasks.get(task_id)
            if task and not task.is_terminal:
                task.status = TaskStatus.QUEUED
                task.assigned_agent = None
                logger.info("Re-queued task %s (agent %s deregistered)", task_id, agent_id)

        logger.info("Agent deregistered: %s (%s)", agent.name, agent_id)
        return True

    def heartbeat(self, agent_id: str) -> bool:
        """Update agent heartbeat. Returns False if agent unknown."""
        agent = self.agents.get(agent_id)
        if agent is None:
            return False
        agent.last_heartbeat = datetime.now(UTC)
        agent.status = AgentStatus.ONLINE
        return True

    # ── Task creation ────────────────────────────────────────────

    def create_tasks_from_plan(
        self,
        state: AppState,
        checks: list,
        context: dict,
    ):
        """
        Build the task queue from a list of resolved checks.

        Uses ChainOrchestrator to produce an execution plan (phases),
        then creates one SwarmTask per check.
        """
        self.reset()
        self.state = state
        self.scan_context = dict(context)
        if "services" not in self.scan_context:
            self.scan_context["services"] = []

        cfg = get_config()

        # Build execution plan via ChainOrchestrator
        orchestrator = ChainOrchestrator(
            scope_domains=self.scan_context.get("scope_domains", []),
            excluded_domains=self.scan_context.get("excluded_domains", []),
        )
        orchestrator.add_checks(checks, suite_resolver=infer_suite)
        phases = orchestrator.get_execution_plan()

        # Build target info from state
        target_info = {
            "url": f"https://{state.target}"
            if not state.target.startswith("http")
            else state.target,
            "domains": self.scan_context.get("scope_domains", [state.target]),
            "ports": cfg.scope.in_scope_ports or [],
        }

        # Create tasks from phases
        for phase in phases:
            phase_task_ids = []
            for check in phase.checks:
                task_id = str(uuid.uuid4())
                task = SwarmTask(
                    task_id=task_id,
                    check_name=check.name,
                    suite=phase.suite,
                    phase_number=phase.phase_number,
                    target=target_info,
                    rate_limit=cfg.swarm.default_rate_limit,
                    timeout_seconds=check.timeout_seconds or cfg.swarm.task_timeout_seconds,
                )
                self.tasks[task_id] = task
                phase_task_ids.append(task_id)

            self.phase_tasks[phase.phase_number] = phase_task_ids

        self.is_running = True
        logger.info(
            "Created %d tasks across %d phases for scan of %s",
            len(self.tasks),
            len(phases),
            state.target,
        )

    # ── Task assignment ──────────────────────────────────────────

    def _phase_complete(self, phase_number: int) -> bool:
        """Check if all tasks in a phase are terminal."""
        task_ids = self.phase_tasks.get(phase_number, [])
        return all(self.tasks[tid].is_terminal for tid in task_ids)

    def _task_dependencies_met(self, task: SwarmTask) -> bool:
        """A task is assignable when all earlier phases are complete."""
        return all(self._phase_complete(pn) for pn in range(1, task.phase_number))

    def get_next_task(self, agent_id: str) -> SwarmTask | None:
        """
        Find the next assignable task for an agent.

        Returns None if nothing is ready or the agent is unknown.
        """
        agent = self.agents.get(agent_id)
        if agent is None:
            return None

        # Respect agent concurrency limit
        active = sum(
            1
            for tid in agent.current_tasks
            if tid in self.tasks and not self.tasks[tid].is_terminal
        )
        if active >= agent.max_concurrent:
            return None

        for task in self.tasks.values():
            if task.status != TaskStatus.QUEUED:
                continue
            if not self._task_dependencies_met(task):
                continue
            # If agent declared capabilities, check suite match
            if agent.capabilities and task.suite not in agent.capabilities:
                continue

            # Assign
            task.status = TaskStatus.ASSIGNED
            task.assigned_agent = agent_id
            # Snapshot current accumulated context for the agent
            task.upstream_context = self._snapshot_context()
            agent.current_tasks.append(task.task_id)

            if self._on_check_start:
                self._on_check_start(task.check_name)

            logger.info(
                "Assigned task %s (%s) to agent %s", task.task_id, task.check_name, agent.name
            )
            return task

        return None

    def _snapshot_context(self) -> dict:
        """
        Serialize the accumulated scan context for transmission to an agent.

        Service objects are converted to dicts; everything else is passed as-is.
        """
        ctx = {}
        for key, value in self.scan_context.items():
            if key == "services":
                ctx["services"] = [
                    svc.to_dict() if isinstance(svc, Service) else svc for svc in value
                ]
            elif isinstance(value, list):
                serialized = []
                for item in value:
                    if hasattr(item, "to_dict"):
                        serialized.append(item.to_dict())
                    else:
                        serialized.append(item)
                ctx[key] = serialized
            else:
                ctx[key] = value
        return ctx

    # ── Task lifecycle ───────────────────────────────────────────

    def start_task(self, task_id: str, agent_id: str) -> bool:
        """Mark task as in-progress."""
        task = self.tasks.get(task_id)
        if task is None or task.assigned_agent != agent_id:
            return False

        task.status = TaskStatus.IN_PROGRESS
        task.started_at = datetime.now(UTC)
        return True

    async def complete_task(self, task_id: str, result: TaskResultPayload) -> bool:
        """
        Mark task complete and merge results into coordinator state.

        This is where observations flow back from agents. If an
        ObservationWriter is set, observations are streamed to the DB.
        """
        task = self.tasks.get(task_id)
        if task is None or task.assigned_agent != result.agent_id:
            return False

        task.status = TaskStatus.COMPLETE
        task.completed_at = datetime.now(UTC)
        task.result = {
            "success": result.success,
            "observations_count": len(result.observations),
            "duration_ms": result.duration_ms,
        }

        # Merge outputs into scan_context (list-append, scalar-replace)
        for key, value in result.outputs.items():
            if (
                key in self.scan_context
                and isinstance(self.scan_context[key], list)
                and isinstance(value, list)
            ):
                existing = {str(v) for v in self.scan_context[key]}
                for item in value:
                    if str(item) not in existing:
                        self.scan_context[key].append(item)
            else:
                self.scan_context[key] = value

        # Merge services
        self._merge_services(result.services)

        # Accumulate observations and stream to DB via writer
        for observation_dict in result.observations:
            self.observations.append(observation_dict)
            if self.observation_writer:
                await self.observation_writer.write(observation_dict)

        # Flush writer after each check completes
        if self.observation_writer and result.observations:
            await self.observation_writer.flush()

        # Update AppState progress counters
        if self.state:
            self.state.checks_completed += 1
            self.state.check_statuses[task.check_name] = "completed" if result.success else "failed"

        if self._on_check_complete:
            self._on_check_complete(task.check_name, result.success, len(result.observations))

        # Clean up agent's current_tasks
        agent = self.agents.get(result.agent_id)
        if agent and task_id in agent.current_tasks:
            agent.current_tasks.remove(task_id)

        logger.info(
            "Task %s (%s) complete: %d observations",
            task_id,
            task.check_name,
            len(result.observations),
        )

        self._check_scan_complete()
        return True

    def fail_task(self, task_id: str, agent_id: str, error: str = "") -> bool:
        """Mark task as failed (no re-queue in Phase 1)."""
        task = self.tasks.get(task_id)
        if task is None:
            return False

        task.status = TaskStatus.FAILED
        task.completed_at = datetime.now(UTC)
        task.error = error

        if self.state:
            self.state.checks_completed += 1
            self.state.check_statuses[task.check_name] = "failed"

        if self._on_check_complete:
            self._on_check_complete(task.check_name, False, 0)

        # Clean up agent's current_tasks
        agent = self.agents.get(agent_id)
        if agent and task_id in agent.current_tasks:
            agent.current_tasks.remove(task_id)

        logger.warning("Task %s (%s) failed: %s", task_id, task.check_name, error)

        self._check_scan_complete()
        return True

    def _merge_services(self, new_services: list[dict]):
        """Merge agent-reported services into scan_context."""
        if not new_services:
            return

        existing = self.scan_context.get("services", [])
        existing_urls = set()
        for svc in existing:
            url = svc.url if isinstance(svc, Service) else svc.get("url", "")
            existing_urls.add(url)

        for svc_dict in new_services:
            url = svc_dict.get("url", "")
            if url and url not in existing_urls:
                existing.append(Service.from_dict(svc_dict))
                existing_urls.add(url)

        self.scan_context["services"] = existing

    def _check_scan_complete(self):
        """If all tasks are terminal, mark the scan as done."""
        if not self.is_running:
            return

        if all(t.is_terminal for t in self.tasks.values()):
            self.is_running = False
            logger.info(
                "Scan complete: %d observations from %d tasks",
                len(self.observations),
                len(self.tasks),
            )

    # ── Status ───────────────────────────────────────────────────

    def get_status(self) -> CoordinatorStatus:
        """Return current coordinator status."""
        status_counts = {}
        for t in self.tasks.values():
            status_counts[t.status] = status_counts.get(t.status, 0) + 1

        current_phase = None
        if self.is_running:
            for t in self.tasks.values():
                if t.status in (TaskStatus.ASSIGNED, TaskStatus.IN_PROGRESS):
                    current_phase = f"Phase {t.phase_number} [{t.suite}]"
                    break

        return CoordinatorStatus(
            is_running=self.is_running,
            agents_online=sum(1 for a in self.agents.values() if a.status == AgentStatus.ONLINE),
            tasks_total=len(self.tasks),
            tasks_queued=status_counts.get(TaskStatus.QUEUED, 0),
            tasks_assigned=status_counts.get(TaskStatus.ASSIGNED, 0),
            tasks_in_progress=status_counts.get(TaskStatus.IN_PROGRESS, 0),
            tasks_complete=status_counts.get(TaskStatus.COMPLETE, 0),
            tasks_failed=status_counts.get(TaskStatus.FAILED, 0),
            observations_count=len(self.observations),
            current_phase=current_phase,
        )

    def list_agents(self) -> list[dict]:
        """Return info for all connected agents."""
        return [a.to_dict() for a in self.agents.values()]


# ── Module-level singleton ───────────────────────────────────────

_coordinator: SwarmCoordinator | None = None


def get_coordinator() -> SwarmCoordinator:
    """Return the singleton SwarmCoordinator instance."""
    global _coordinator
    if _coordinator is None:
        _coordinator = SwarmCoordinator()
    return _coordinator
