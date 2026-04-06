"""
Tests for app/checks/runner.py

Covers:
- CheckRunner initialization
- Check registration and scope validator injection
- Scope checking (is_in_scope) with wildcards and exclusions
- Run loop: condition-based scheduling
- Sequential vs parallel execution
- Context accumulation (outputs, services, findings)
- Finding ID assignment
- Service merging and deduplication
- Pause/stop/resume controls
- Diagnostics and check tree
"""

import asyncio
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Finding, Service
from app.checks.runner import CheckRunner

import pytest

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


class FindingProducingCheck(BaseCheck):
    """Check that produces findings."""

    name = "finding_check"
    description = "Produces findings"
    conditions = []

    def __init__(self, finding_count: int = 1, preset_ids: bool = False):
        super().__init__()
        self.finding_count = finding_count
        self.preset_ids = preset_ids

    async def run(self, context: dict[str, Any]) -> CheckResult:
        findings = []
        for i in range(self.finding_count):
            findings.append(
                Finding(
                    id=f"PRESET-{i}" if self.preset_ids else "",
                    title=f"Finding {i}",
                    description=f"Description {i}",
                    severity="medium",
                    evidence=f"Evidence {i}",
                )
            )
        return CheckResult(success=True, findings=findings)


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
# CheckRunner Initialization Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckRunnerInit:
    """Tests for CheckRunner initialization."""

    def test_default_initialization(self):
        """Runner initializes with sensible defaults."""
        runner = CheckRunner()

        assert runner.event_callback is None
        assert runner.parallel is False
        assert runner.scope_domains == []
        assert runner.excluded_domains == []
        assert runner.checks == []
        assert runner.context == {}
        assert runner.findings == []
        assert runner.is_running is False
        assert runner.is_paused is False

    def test_initialization_with_scope(self):
        """Runner accepts scope configuration."""
        runner = CheckRunner(
            scope_domains=["example.com", "*.test.com"],
            excluded_domains=["admin.example.com"],
        )

        assert runner.scope_domains == ["example.com", "*.test.com"]
        assert runner.excluded_domains == ["admin.example.com"]

    def test_initialization_with_parallel(self):
        """Runner accepts parallel flag."""
        runner = CheckRunner(parallel=True)
        assert runner.parallel is True


# ═══════════════════════════════════════════════════════════════════════════════
# Check Registration Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckRegistration:
    """Tests for check registration."""

    def test_register_check(self):
        """Check is added to runner's check list."""
        runner = CheckRunner()
        check = SimpleCheck()

        runner.register_check(check)

        assert len(runner.checks) == 1
        assert runner.checks[0] is check

    def test_register_multiple_checks(self):
        """Multiple checks can be registered."""
        runner = CheckRunner()
        check1 = SimpleCheck()
        check2 = DependentCheck()

        runner.register_check(check1)
        runner.register_check(check2)

        assert len(runner.checks) == 2

    def test_scope_validator_injected(self):
        """Scope validator is set on registered checks."""
        runner = CheckRunner(scope_domains=["example.com"])
        check = SimpleCheck()

        runner.register_check(check)

        # Check should now use runner's scope validator
        assert check._scope_validator is not None
        assert check.is_in_scope("http://example.com") is True
        assert check.is_in_scope("http://other.com") is False


# ═══════════════════════════════════════════════════════════════════════════════
# Scope Checking Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestScopeChecking:
    """Tests for is_in_scope method."""

    def test_no_scope_allows_all(self):
        """Without scope_domains, all URLs are in scope."""
        runner = CheckRunner()

        assert runner.is_in_scope("http://anything.com") is True
        assert runner.is_in_scope("http://example.com:8080/path") is True

    def test_exact_domain_match(self):
        """Exact domain match works."""
        runner = CheckRunner(scope_domains=["example.com"])

        assert runner.is_in_scope("http://example.com") is True
        assert runner.is_in_scope("http://example.com:8080") is True
        assert runner.is_in_scope("https://example.com/path") is True
        assert runner.is_in_scope("http://other.com") is False

    def test_wildcard_domain_match(self):
        """Wildcard patterns work."""
        runner = CheckRunner(scope_domains=["*.example.com"])

        assert runner.is_in_scope("http://api.example.com") is True
        assert runner.is_in_scope("http://sub.api.example.com") is True
        assert runner.is_in_scope("http://example.com") is False  # No subdomain
        assert runner.is_in_scope("http://other.com") is False

    def test_exclusions_override_scope(self):
        """Excluded domains take precedence over scope."""
        runner = CheckRunner(
            scope_domains=["*.example.com"],
            excluded_domains=["admin.example.com"],
        )

        assert runner.is_in_scope("http://api.example.com") is True
        assert runner.is_in_scope("http://admin.example.com") is False

    def test_invalid_url_returns_false(self):
        """Invalid URLs return False."""
        runner = CheckRunner(scope_domains=["example.com"])

        assert runner.is_in_scope("not-a-url") is False
        assert runner.is_in_scope("") is False

    def test_multiple_scope_domains(self):
        """Multiple scope domains are checked."""
        runner = CheckRunner(scope_domains=["example.com", "test.com"])

        assert runner.is_in_scope("http://example.com") is True
        assert runner.is_in_scope("http://test.com") is True
        assert runner.is_in_scope("http://other.com") is False


# ═══════════════════════════════════════════════════════════════════════════════
# Run Loop Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRunLoop:
    """Tests for the main run loop."""

    async def test_runs_check_with_no_conditions(self):
        """Checks with no conditions run immediately."""
        runner = CheckRunner()
        check = SimpleCheck()
        runner.register_check(check)

        await runner.run()

        assert check.was_run is True
        assert runner.checks_run == 1

    async def test_runs_dependent_checks_in_order(self):
        """Dependent checks run after their dependencies."""
        runner = CheckRunner()
        simple = SimpleCheck()
        dependent = DependentCheck()

        runner.register_check(dependent)  # Register dependent first
        runner.register_check(simple)

        await runner.run()

        assert simple.was_run is True
        assert dependent.was_run is True
        assert "simple_output" in dependent.received_context

    async def test_unmet_conditions_prevent_execution(self):
        """Checks with unmet conditions don't run."""
        runner = CheckRunner()
        dependent = DependentCheck()  # Needs simple_output

        runner.register_check(dependent)

        await runner.run()

        assert dependent.was_run is False

    async def test_context_propagates_between_checks(self):
        """Outputs from checks are added to context."""
        runner = CheckRunner()
        simple = SimpleCheck(output_value="test_value")
        dependent = DependentCheck()

        runner.register_check(simple)
        runner.register_check(dependent)

        await runner.run()

        assert runner.context["simple_output"] == "test_value"
        assert runner.context["dependent_output"] == "dependent_result"

    async def test_initial_context_preserved(self):
        """Initial context is available to checks."""
        runner = CheckRunner()
        dependent = DependentCheck()
        runner.register_check(dependent)

        await runner.run(initial_context={"simple_output": "pre-existing"})

        assert dependent.was_run is True
        assert dependent.received_context["simple_output"] == "pre-existing"

    async def test_services_initialized_in_context(self):
        """Services list is initialized if not present."""
        runner = CheckRunner()
        check = SimpleCheck()
        runner.register_check(check)

        await runner.run()

        assert "services" in runner.context
        assert runner.context["services"] == []

    async def test_max_iterations_safety(self):
        """Run loop has safety limit on iterations."""
        # This is hard to test directly, but we can verify
        # the loop terminates even with no checks
        runner = CheckRunner()

        await runner.run()

        assert runner.is_running is False


# ═══════════════════════════════════════════════════════════════════════════════
# Parallel Execution Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestParallelExecution:
    """Tests for parallel check execution."""

    async def test_sequential_execution_default(self):
        """By default, checks run sequentially."""
        runner = CheckRunner(parallel=False)
        check1 = SlowCheck(delay=0.05)
        check2 = SlowCheck(delay=0.05)
        check1.name = "slow_1"
        check2.name = "slow_2"

        runner.register_check(check1)
        runner.register_check(check2)

        import time

        start = time.time()
        await runner.run()
        elapsed = time.time() - start

        # Sequential: should take ~0.1s
        assert elapsed >= 0.09

    async def test_parallel_execution(self):
        """With parallel=True, checks run concurrently."""
        runner = CheckRunner(parallel=True)
        check1 = SlowCheck(delay=0.05)
        check2 = SlowCheck(delay=0.05)
        check1.name = "slow_1"
        check2.name = "slow_2"

        runner.register_check(check1)
        runner.register_check(check2)

        import time

        start = time.time()
        await runner.run()
        elapsed = time.time() - start

        # Parallel: should take ~0.05s (plus overhead)
        assert elapsed < 0.09


# ═══════════════════════════════════════════════════════════════════════════════
# Finding Handling Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFindingHandling:
    """Tests for finding collection and ID assignment."""

    async def test_findings_collected(self):
        """Findings from checks are collected."""
        runner = CheckRunner()
        check = FindingProducingCheck(finding_count=3)
        runner.register_check(check)

        findings = await runner.run()

        assert len(findings) == 3
        assert len(runner.findings) == 3

    async def test_finding_ids_assigned(self):
        """Findings without IDs get sequential IDs."""
        runner = CheckRunner()
        check = FindingProducingCheck(finding_count=3, preset_ids=False)
        runner.register_check(check)

        findings = await runner.run()

        assert findings[0].id == "F-001"
        assert findings[1].id == "F-002"
        assert findings[2].id == "F-003"

    async def test_preset_ids_preserved(self):
        """Findings with preset IDs keep them."""
        runner = CheckRunner()
        check = FindingProducingCheck(finding_count=2, preset_ids=True)
        runner.register_check(check)

        findings = await runner.run()

        assert findings[0].id == "PRESET-0"
        assert findings[1].id == "PRESET-1"

    async def test_findings_from_multiple_checks(self):
        """Findings from multiple checks are accumulated."""
        runner = CheckRunner()
        check1 = FindingProducingCheck(finding_count=2)
        check2 = FindingProducingCheck(finding_count=3)
        check1.name = "check_1"
        check2.name = "check_2"

        runner.register_check(check1)
        runner.register_check(check2)

        findings = await runner.run()

        assert len(findings) == 5
        # IDs should be sequential across checks
        assert findings[4].id == "F-005"


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
        assert "findings_count" in diag
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
