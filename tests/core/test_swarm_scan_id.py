"""
The scan id travels with every swarm task (phase 57 §0.5 gap).

A remote check needs the coordinator's scan id for three things: capture
attribution (`BaseCheck.execute()`), grading (`grade_result()` reads the corpus
and binds candidates under it) and the agent-side window Guardian, which stamps
the violations it records. Before this fix the id reached the agent only as a
side effect — the scanner puts it in the scan context and the coordinator
snapshots that whole dict into `upstream_context` — and the window Guardian was
built without it. The id is now an explicit field on the task and the payload.
"""

import pytest

from app.checks.base import CheckResult
from app.gates.guardian import Guardian
from app.scan_session import ScanSession
from app.swarm.agent import SwarmAgent
from app.swarm.coordinator import SwarmCoordinator
from app.swarm.models import SwarmTask, TaskPayload

pytestmark = pytest.mark.unit

TARGET = {"url": "https://acme.test", "domains": ["acme.test"], "ports": []}


class _FakeCheck:
    """Records the context it ran with; produces nothing."""

    def __init__(self, name: str):
        self.name = name
        self.produces: list = []
        self.conditions: list = []
        self.timeout_seconds = 30
        self.requests_per_second = 10.0
        self.seen_context: dict | None = None

    def set_scope_validator(self, validator):
        self._validator = validator

    async def execute(self, context):
        self.seen_context = context
        return CheckResult(success=True)


def _agent_with(check: _FakeCheck) -> SwarmAgent:
    """An agent without the network or the 133-check registry."""
    agent = SwarmAgent.__new__(SwarmAgent)
    agent._checks_by_name = {check.name: check}
    return agent


def _task_data(**overrides) -> dict:
    data = {
        "task_id": "task-1",
        "check_name": "web_fake",
        "target": TARGET,
        "upstream_context": {},
    }
    data.update(overrides)
    return data


# ── coordinator → payload ────────────────────────────────────────────


def test_the_payload_carries_the_tasks_scan_id():
    task = SwarmTask(
        task_id="t",
        check_name="web_fake",
        suite="web",
        phase_number=1,
        target=TARGET,
        scan_id="scan-1",
    )
    assert TaskPayload.from_swarm_task(task).model_dump()["scan_id"] == "scan-1"


def test_the_coordinator_stamps_every_task_with_the_session_id():
    """Even when the scan context it was handed carries no `scan_id` — the id
    comes from the session, not from whatever the context happened to hold."""
    coordinator = SwarmCoordinator()
    session = ScanSession(id="scan-xyz", target="acme.test")
    checks = [_FakeCheck("network_fake"), _FakeCheck("web_fake")]

    coordinator.create_tasks_from_plan(session, checks, {"scope_domains": ["acme.test"]})

    assert len(coordinator.tasks) == 2
    assert {task.scan_id for task in coordinator.tasks.values()} == {"scan-xyz"}


# ── payload → agent → check ──────────────────────────────────────────


async def test_the_agent_hands_the_payload_scan_id_to_the_check():
    check = _FakeCheck("web_fake")
    await _agent_with(check)._execute_task(_task_data(scan_id="scan-1"))

    assert check.seen_context["scan_id"] == "scan-1"


async def test_the_payload_scan_id_wins_over_a_stale_upstream_one():
    check = _FakeCheck("web_fake")
    await _agent_with(check)._execute_task(
        _task_data(scan_id="scan-1", upstream_context={"scan_id": "stale"})
    )

    assert check.seen_context["scan_id"] == "scan-1"


async def test_a_payload_from_an_older_coordinator_falls_back_to_upstream():
    check = _FakeCheck("web_fake")
    await _agent_with(check)._execute_task(_task_data(upstream_context={"scan_id": "scan-old"}))

    assert check.seen_context["scan_id"] == "scan-old"


async def test_no_scan_id_anywhere_leaves_the_context_without_one():
    check = _FakeCheck("web_fake")
    await _agent_with(check)._execute_task(_task_data())

    assert "scan_id" not in check.seen_context


# ── the agent-side window Guardian ───────────────────────────────────


async def test_the_window_guardian_is_built_with_the_scan_id(monkeypatch):
    """So a window violation the agent records is attributable to its scan."""
    built: dict = {}
    original = Guardian.from_scope

    def spy(*args, **kwargs):
        built.update(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(Guardian, "from_scope", spy)

    check = _FakeCheck("web_fake")
    window = {"start": "2000-01-01T00:00:00+00:00", "end": "2999-01-01T00:00:00+00:00"}
    await _agent_with(check)._execute_task(_task_data(scan_id="scan-1", scan_window=window))

    assert built["scan_id"] == "scan-1"
    assert check.seen_context["scan_id"] == "scan-1"
