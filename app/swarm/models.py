"""
app/swarm/models.py - Data models for swarm coordination.

Dataclasses for internal state, Pydantic models for API payloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

# ── Enums ────────────────────────────────────────────────────────


class TaskStatus(StrEnum):
    QUEUED = "queued"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    FAILED = "failed"


class AgentStatus(StrEnum):
    ONLINE = "online"
    STALE = "stale"
    OFFLINE = "offline"


# ── Internal dataclasses ─────────────────────────────────────────


@dataclass
class SwarmTask:
    """A single check assigned (or assignable) to an agent."""

    task_id: str
    check_name: str
    suite: str
    phase_number: int
    target: dict  # {url, domains, ports}
    upstream_context: dict = field(default_factory=dict)
    rate_limit: float = 10.0  # requests per second
    timeout_seconds: int = 300
    engagement_window: dict | None = None
    outside_window_acknowledged: bool = False
    status: TaskStatus = TaskStatus.QUEUED
    assigned_agent: str | None = None
    result: dict | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @property
    def is_terminal(self) -> bool:
        return self.status in (TaskStatus.COMPLETE, TaskStatus.FAILED)


@dataclass
class AgentInfo:
    """A connected swarm agent."""

    agent_id: str
    name: str
    api_key_name: str
    capabilities: list[str] = field(default_factory=list)  # suite names
    max_concurrent: int = 3
    registered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: AgentStatus = AgentStatus.ONLINE
    current_tasks: list[str] = field(default_factory=list)  # task_ids

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "capabilities": self.capabilities,
            "max_concurrent": self.max_concurrent,
            "registered_at": self.registered_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "status": self.status.value,
            "current_tasks": self.current_tasks,
        }


# ── Pydantic API models ─────────────────────────────────────────


class RegisterRequest(BaseModel):
    name: str = Field(default="", description="Human-readable agent name")
    capabilities: list[str] = Field(
        default_factory=list, description="Suite names this agent can run"
    )
    max_concurrent: int = Field(default=3, ge=1, le=50)


class RegisterResponse(BaseModel):
    agent_id: str
    config: dict = Field(default_factory=dict, description="Coordinator-assigned config")


class HeartbeatRequest(BaseModel):
    agent_id: str


class TaskTarget(BaseModel):
    url: str
    domains: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)


class TaskPayload(BaseModel):
    """Sent to agent when it polls for work."""

    task_id: str
    check_name: str
    suite: str
    check_config: dict = Field(default_factory=dict)
    target: TaskTarget
    upstream_context: dict = Field(default_factory=dict)
    rate_limit: float = 10.0
    timeout_seconds: int = 300
    engagement_window: dict | None = None  # {start, end} ISO datetimes
    outside_window_acknowledged: bool = False

    @classmethod
    def from_swarm_task(cls, task: SwarmTask) -> TaskPayload:
        return cls(
            task_id=task.task_id,
            check_name=task.check_name,
            suite=task.suite,
            target=TaskTarget(**task.target),
            upstream_context=task.upstream_context,
            rate_limit=task.rate_limit,
            timeout_seconds=task.timeout_seconds,
            engagement_window=getattr(task, "engagement_window", None),
            outside_window_acknowledged=getattr(task, "outside_window_acknowledged", False),
        )


class TaskStartRequest(BaseModel):
    agent_id: str


class TaskResultPayload(BaseModel):
    """Submitted by agent when a check completes."""

    agent_id: str
    success: bool = True
    observations: list[dict] = Field(default_factory=list)
    outputs: dict = Field(default_factory=dict)
    services: list[dict] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    duration_ms: int = 0


class TaskFailPayload(BaseModel):
    agent_id: str
    error: str = ""


class CoordinatorStatus(BaseModel):
    is_running: bool = False
    agents_online: int = 0
    tasks_total: int = 0
    tasks_queued: int = 0
    tasks_assigned: int = 0
    tasks_in_progress: int = 0
    tasks_complete: int = 0
    tasks_failed: int = 0
    observations_count: int = 0
    current_phase: str | None = None


class KeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)


class KeyInfo(BaseModel):
    key_id: str
    name: str
    created_at: str
    last_used_at: str | None = None
