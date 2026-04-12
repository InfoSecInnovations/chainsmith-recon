"""Tests for CheckRunner observation/service handling, error handling, controls, diagnostics, and event callbacks."""

import asyncio
from typing import Any

import pytest

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Observation, Service
from app.checks.runner import CheckRunner

pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# Test Helpers - Concrete Check Implementations
# ═══════════════════════════════════════════════════════════════════════════════


class SimpleCheck(BaseCheck):
    """Check with no conditions that produces an output."""

    name = "simple_check"
    description = "A simple check"
    conditions = []
    produces = ["simple_output"]

    def __init__(self, output_value: Any = "simple_result"):
        super().__init__()
        self.output_value = output_value
        self.was_run = False

    async def run(self, context: dict[str, Any]) -> CheckResult:
        self.was_run = True
        return CheckResult(success=True, outputs={"simple_output": self.output_value})


class DependentCheck(BaseCheck):
    """Check that depends on simple_output being truthy."""

    name = "dependent_check"
    description = "Depends on simple_output"
    conditions = [CheckCondition("simple_output", "truthy")]
    produces = ["dependent_output"]

    def __init__(self):
        super().__init__()
        self.was_run = False
        self.received_context = None

    async def run(self, context: dict[str, Any]) -> CheckResult:
        self.was_run = True
        self.received_context = context.copy()
        return CheckResult(success=True, outputs={"dependent_output": "dependent_result"})


class ObservationProducingCheck(BaseCheck):
    """Check that produces observations."""

    name = "observation_check"
    description = "Produces observations"
    conditions = []

    def __init__(self, observation_count: int = 1, preset_ids: bool = False):
        super().__init__()
        self.observation_count = observation_count
        self.preset_ids = preset_ids

    async def run(self, context: dict[str, Any]) -> CheckResult:
        observations = []
        for i in range(self.observation_count):
            observations.append(
                Observation(
                    id=f"PRESET-{i}" if self.preset_ids else "",
                    title=f"Observation {i}",
                    description=f"Description {i}",
                    severity="medium",
                    evidence=f"Evidence {i}",
                )
            )
        return CheckResult(success=True, observations=observations)


class ServiceDiscoveringCheck(BaseCheck):
    """Check that discovers services."""

    name = "service_discovering_check"
    description = "Discovers services"
    conditions = []

    def __init__(self, services: list[Service] = None):
        super().__init__()
        self.services_to_return = services or []

    async def run(self, context: dict[str, Any]) -> CheckResult:
        return CheckResult(success=True, services=self.services_to_return)


class FailingCheck(BaseCheck):
    """Check that fails."""

    name = "failing_check"
    description = "Always fails"
    conditions = []

    async def run(self, context: dict[str, Any]) -> CheckResult:
        raise RuntimeError("Intentional failure")


class SlowCheck(BaseCheck):
    """Check that takes time."""

    name = "slow_check"
    description = "Slow check"
    conditions = []
    timeout_seconds = 5.0

    def __init__(self, delay: float = 0.1):
        super().__init__()
        self.delay = delay
        self.was_run = False

    async def run(self, context: dict[str, Any]) -> CheckResult:
        self.was_run = True
        await asyncio.sleep(self.delay)
        return CheckResult(success=True, outputs={"slow_output": "done"})


# ═══════════════════════════════════════════════════════════════════════════════
# Observation Handling Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestObservationHandling:
    """Tests for observation collection and ID assignment."""

    async def test_observations_collected(self):
        """Observations from checks are collected."""
        runner = CheckRunner()
        check = ObservationProducingCheck(observation_count=3)
        runner.register_check(check)

        observations = await runner.run()

        assert len(observations) == 3
        assert len(runner.observations) == 3

    async def test_observation_ids_assigned(self):
        """Observations without IDs get sequential IDs."""
        runner = CheckRunner()
        check = ObservationProducingCheck(observation_count=3, preset_ids=False)
        runner.register_check(check)

        observations = await runner.run()

        assert observations[0].id == "F-001"
        assert observations[1].id == "F-002"
        assert observations[2].id == "F-003"

    async def test_preset_ids_preserved(self):
        """Observations with preset IDs keep them."""
        runner = CheckRunner()
        check = ObservationProducingCheck(observation_count=2, preset_ids=True)
        runner.register_check(check)

        observations = await runner.run()

        assert observations[0].id == "PRESET-0"
        assert observations[1].id == "PRESET-1"

    async def test_observations_from_multiple_checks(self):
        """Observations from multiple checks are accumulated."""
        runner = CheckRunner()
        check1 = ObservationProducingCheck(observation_count=2)
        check2 = ObservationProducingCheck(observation_count=3)
        check1.name = "check_1"
        check2.name = "check_2"

        runner.register_check(check1)
        runner.register_check(check2)

        observations = await runner.run()

        assert len(observations) == 5
        # IDs should be sequential across checks
        assert observations[4].id == "F-005"

    async def test_observation_missing_required_fields(self):
        """Observations with missing required fields are handled gracefully."""

        class MalformedObservationCheck(BaseCheck):
            name = "malformed_obs_check"
            description = "Produces an observation missing fields"
            conditions = []

            async def run(self, context: dict) -> CheckResult:
                # Create observation with empty title and missing description
                obs = Observation(
                    id="",
                    title="",
                    description="",
                    severity="medium",
                    evidence="",
                )
                return CheckResult(success=True, observations=[obs])

        runner = CheckRunner()
        runner.register_check(MalformedObservationCheck())

        observations = await runner.run()

        # Runner should still collect the observation (it assigns an ID)
        assert len(observations) == 1
        assert observations[0].id == "F-001"
        assert observations[0].title == ""
        assert observations[0].evidence == ""


# ═══════════════════════════════════════════════════════════════════════════════
# Service Handling Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestServiceHandling:
    """Tests for service discovery and merging."""

    async def test_services_added_to_context(self):
        """Discovered services are added to context."""
        runner = CheckRunner()
        services = [
            Service(url="http://svc1.local:80", host="svc1.local", port=80),
            Service(url="http://svc2.local:8080", host="svc2.local", port=8080),
        ]
        check = ServiceDiscoveringCheck(services=services)
        runner.register_check(check)

        await runner.run()

        assert len(runner.context["services"]) == 2

    async def test_duplicate_services_not_added(self):
        """Services with same URL are not duplicated."""
        runner = CheckRunner()
        svc = Service(url="http://svc.local:80", host="svc.local", port=80)

        check1 = ServiceDiscoveringCheck(services=[svc])
        check2 = ServiceDiscoveringCheck(services=[svc])
        check1.name = "discover_1"
        check2.name = "discover_2"

        runner.register_check(check1)
        runner.register_check(check2)

        await runner.run()

        assert len(runner.context["services"]) == 1

    async def test_service_metadata_merged(self):
        """When same service found again, metadata is merged."""
        runner = CheckRunner()

        svc1 = Service(
            url="http://svc.local:80",
            host="svc.local",
            port=80,
            metadata={"key1": "value1"},
        )
        svc2 = Service(
            url="http://svc.local:80",
            host="svc.local",
            port=80,
            metadata={"key2": "value2"},
        )

        check1 = ServiceDiscoveringCheck(services=[svc1])
        check2 = ServiceDiscoveringCheck(services=[svc2])
        check1.name = "discover_1"
        check2.name = "discover_2"

        runner.register_check(check1)
        runner.register_check(check2)

        await runner.run()

        services = runner.context["services"]
        assert len(services) == 1
        assert services[0].metadata.get("key1") == "value1"
        assert services[0].metadata.get("key2") == "value2"


# ═══════════════════════════════════════════════════════════════════════════════
# Error Handling Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestErrorHandling:
    """Tests for error handling during execution."""

    async def test_failed_check_counted(self):
        """Failed checks increment failure counter."""
        runner = CheckRunner()
        check = FailingCheck()
        runner.register_check(check)

        await runner.run()

        assert runner.checks_failed == 1
        assert runner.checks_run == 1

    async def test_failed_check_doesnt_stop_others(self):
        """Other checks still run after a failure."""
        runner = CheckRunner()
        failing = FailingCheck()
        simple = SimpleCheck()

        runner.register_check(failing)
        runner.register_check(simple)

        await runner.run()

        assert simple.was_run is True
        assert runner.checks_run == 2


# ═══════════════════════════════════════════════════════════════════════════════
# Control Tests (stop/pause/resume)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRunnerControls:
    """Tests for stop/pause/resume functionality."""

    async def test_stop_terminates_run(self):
        """Calling stop() terminates the run loop."""
        runner = CheckRunner()
        slow = SlowCheck(delay=1.0)
        runner.register_check(slow)

        async def stop_after_delay():
            await asyncio.sleep(0.05)
            runner.stop()

        # Start stop task
        asyncio.create_task(stop_after_delay())

        await runner.run()

        assert runner.is_running is False

    def test_pause_sets_flag(self):
        """pause() sets is_paused flag."""
        runner = CheckRunner()
        runner.pause()
        assert runner.is_paused is True

    def test_resume_clears_flag(self):
        """resume() clears is_paused flag."""
        runner = CheckRunner()
        runner.pause()
        runner.resume()
        assert runner.is_paused is False


# ═══════════════════════════════════════════════════════════════════════════════
# Diagnostics Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDiagnostics:
    """Tests for diagnostic methods."""

    async def test_get_check_tree(self):
        """get_check_tree returns check info and context keys."""
        runner = CheckRunner()
        check = SimpleCheck()
        runner.register_check(check)

        await runner.run()

        tree = runner.get_check_tree()

        assert "checks" in tree
        assert "context_keys" in tree
        assert len(tree["checks"]) == 1
        assert tree["checks"][0]["name"] == "simple_check"
        assert "simple_output" in tree["context_keys"]

    async def test_get_diagnostics(self):
        """get_diagnostics returns detailed check state."""
        runner = CheckRunner()
        simple = SimpleCheck()
        dependent = DependentCheck()

        runner.register_check(simple)
        runner.register_check(dependent)

        await runner.run()

        diag = runner.get_diagnostics()

        assert "context_keys" in diag
        assert "services_count" in diag
        assert "observations_count" in diag
        assert "checks" in diag
        assert len(diag["checks"]) == 2

        # Find the simple check diagnostics
        simple_diag = next(c for c in diag["checks"] if c["name"] == "simple_check")
        assert simple_diag["status"] == "completed"
        assert simple_diag["can_run"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# Event Callback Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestEventCallback:
    """Tests for event emission."""

    async def test_emit_calls_callback(self):
        """emit() calls the event callback."""
        events = []

        async def callback(event):
            events.append(event)

        runner = CheckRunner(event_callback=callback)

        await runner.emit({"type": "test", "data": "value"})

        assert len(events) == 1
        assert events[0]["type"] == "test"

    async def test_emit_no_callback_is_noop(self):
        """emit() is a no-op without callback."""
        runner = CheckRunner()

        # Should not raise
        await runner.emit({"type": "test"})
