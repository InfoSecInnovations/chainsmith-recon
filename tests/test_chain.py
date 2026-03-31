"""
Tests for app/checks/chain.py - Chain Orchestrator

Covers:
- Suite ordering
- Dependency resolution
- Execution plan generation
- Phase execution
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.checks.base import BaseCheck, CheckResult, CheckCondition, Service
from app.checks.chain import (
    ChainOrchestrator,
    CheckNode,
    ExecutionPhase,
    SUITE_ORDER,
    SUITE_DEPENDENCIES,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


class MockCheck(BaseCheck):
    """Mock check for testing."""
    
    def __init__(self, name: str, conditions: list = None, produces: list = None):
        super().__init__()
        self.name = name
        self.conditions = conditions or []
        self.produces = produces or []
        self._run_called = False
    
    async def run(self, context: dict) -> CheckResult:
        self._run_called = True
        return CheckResult(
            success=True,
            outputs={p: [f"{self.name}_value"] for p in self.produces},
        )


@pytest.fixture
def orchestrator():
    """Create a fresh orchestrator."""
    return ChainOrchestrator()


# ═══════════════════════════════════════════════════════════════════════════════
# Suite Ordering Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSuiteOrdering:
    """Tests for suite ordering."""

    def test_suite_order_defined(self):
        """Test that suite order is defined."""
        assert len(SUITE_ORDER) >= 7
        assert "network" in SUITE_ORDER
        assert "web" in SUITE_ORDER
        assert "ai" in SUITE_ORDER
        assert "mcp" in SUITE_ORDER
        assert "agent" in SUITE_ORDER
        assert "rag" in SUITE_ORDER
        assert "cag" in SUITE_ORDER

    def test_network_is_first(self):
        """Test that network suite runs first."""
        assert SUITE_ORDER[0] == "network"

    def test_suite_dependencies_defined(self):
        """Test suite dependencies are defined."""
        assert "network" in SUITE_DEPENDENCIES
        assert SUITE_DEPENDENCIES["network"] == []  # No deps
        assert "network" in SUITE_DEPENDENCIES["web"]
        assert "network" in SUITE_DEPENDENCIES["ai"]


# ═══════════════════════════════════════════════════════════════════════════════
# Dependency Resolution Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDependencyResolution:
    """Tests for check dependency resolution."""

    def test_add_check(self, orchestrator):
        """Test adding a single check."""
        check = MockCheck("test_check")
        orchestrator.add_check(check, suite="network")
        
        assert "test_check" in orchestrator.nodes
        assert orchestrator.nodes["test_check"].suite == "network"

    def test_add_checks_with_suite_resolver(self, orchestrator):
        """Test adding checks with suite resolver."""
        checks = [
            MockCheck("dns_check"),
            MockCheck("web_check"),
        ]
        
        def resolver(name):
            if "dns" in name:
                return "network"
            return "web"
        
        orchestrator.add_checks(checks, suite_resolver=resolver)
        
        assert orchestrator.nodes["dns_check"].suite == "network"
        assert orchestrator.nodes["web_check"].suite == "web"

    def test_dependency_graph_built(self, orchestrator):
        """Test dependency graph is built from produces/conditions."""
        check1 = MockCheck("producer", produces=["data"])
        check2 = MockCheck(
            "consumer",
            conditions=[CheckCondition("data", "truthy")],
        )
        
        orchestrator.add_check(check1, suite="network")
        orchestrator.add_check(check2, suite="network")
        orchestrator._build_dependency_graph()
        
        consumer_node = orchestrator.nodes["consumer"]
        assert "producer" in consumer_node.dependencies

    def test_infer_suite_from_name(self, orchestrator):
        """Test suite inference from check name."""
        check = MockCheck("dns_enumeration")
        orchestrator.add_checks([check])
        
        assert orchestrator.nodes["dns_enumeration"].suite == "network"

    def test_infer_suite_mcp(self, orchestrator):
        """Test suite inference for MCP checks."""
        check = MockCheck("mcp_discovery")
        orchestrator.add_checks([check])
        
        assert orchestrator.nodes["mcp_discovery"].suite == "mcp"

    def test_infer_suite_agent(self, orchestrator):
        """Test suite inference for agent checks."""
        check = MockCheck("agent_discovery")
        orchestrator.add_checks([check])
        
        assert orchestrator.nodes["agent_discovery"].suite == "agent"


# ═══════════════════════════════════════════════════════════════════════════════
# Execution Plan Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestExecutionPlan:
    """Tests for execution plan generation."""

    def test_empty_plan(self, orchestrator):
        """Test empty orchestrator returns empty plan."""
        plan = orchestrator.get_execution_plan()
        assert plan == []

    def test_single_check_plan(self, orchestrator):
        """Test plan with single check."""
        check = MockCheck("solo_check")
        orchestrator.add_check(check, suite="network")
        
        plan = orchestrator.get_execution_plan()
        
        assert len(plan) == 1
        assert plan[0].suite == "network"
        assert len(plan[0].checks) == 1

    def test_dependency_ordering(self, orchestrator):
        """Test dependent checks come after producers."""
        producer = MockCheck("producer", produces=["data"])
        consumer = MockCheck(
            "consumer",
            conditions=[CheckCondition("data", "truthy")],
        )
        
        orchestrator.add_check(consumer, suite="network")  # Add consumer first
        orchestrator.add_check(producer, suite="network")
        orchestrator._build_dependency_graph()
        
        plan = orchestrator.get_execution_plan()
        
        # Producer should be in earlier phase
        producer_phase = None
        consumer_phase = None
        
        for phase in plan:
            for check in phase.checks:
                if check.name == "producer":
                    producer_phase = phase.phase_number
                elif check.name == "consumer":
                    consumer_phase = phase.phase_number
        
        assert producer_phase is not None
        assert consumer_phase is not None
        assert producer_phase < consumer_phase

    def test_suite_ordering_in_plan(self, orchestrator):
        """Test suites appear in correct order."""
        network_check = MockCheck("network_check")
        web_check = MockCheck("web_check")
        ai_check = MockCheck("ai_check")
        
        # Add in reverse order
        orchestrator.add_check(ai_check, suite="ai")
        orchestrator.add_check(web_check, suite="web")
        orchestrator.add_check(network_check, suite="network")
        
        plan = orchestrator.get_execution_plan()
        
        suite_order = [p.suite for p in plan]
        
        assert suite_order.index("network") < suite_order.index("web")
        assert suite_order.index("web") < suite_order.index("ai")

    def test_parallel_flag_propagates(self):
        """Test parallel flag propagates to phases."""
        orchestrator = ChainOrchestrator(parallel_within_phase=True)
        
        check1 = MockCheck("check1")
        check2 = MockCheck("check2")
        
        orchestrator.add_check(check1, suite="network")
        orchestrator.add_check(check2, suite="network")
        
        plan = orchestrator.get_execution_plan()
        
        # First phase with multiple checks should be parallel
        multi_check_phases = [p for p in plan if len(p.checks) > 1]
        if multi_check_phases:
            assert multi_check_phases[0].parallel


# ═══════════════════════════════════════════════════════════════════════════════
# Execution Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestExecution:
    """Tests for check execution."""

    @pytest.mark.asyncio
    async def test_run_single_check(self, orchestrator):
        """Test running a single check."""
        check = MockCheck("test_check", produces=["result"])
        orchestrator.add_check(check, suite="network")
        
        findings = await orchestrator.run({"target": "example.com"})
        
        assert check._run_called
        assert "result" in orchestrator.context

    @pytest.mark.asyncio
    async def test_context_propagates(self, orchestrator):
        """Test context propagates between checks."""
        producer = MockCheck("producer", produces=["data"])
        consumer = MockCheck(
            "consumer",
            conditions=[CheckCondition("data", "truthy")],
        )
        
        orchestrator.add_check(producer, suite="network")
        orchestrator.add_check(consumer, suite="network")
        orchestrator._build_dependency_graph()
        
        await orchestrator.run({})
        
        assert producer._run_called
        assert consumer._run_called
        assert "data" in orchestrator.context

    @pytest.mark.asyncio
    async def test_skips_unsatisfied_conditions(self, orchestrator):
        """Test checks with unsatisfied conditions are skipped."""
        check = MockCheck(
            "needs_data",
            conditions=[CheckCondition("missing_data", "truthy")],
        )
        orchestrator.add_check(check, suite="network")
        
        await orchestrator.run({})
        
        assert not check._run_called
        assert orchestrator.checks_skipped > 0

    @pytest.mark.asyncio
    async def test_events_emitted(self):
        """Test events are emitted during execution."""
        events = []
        
        async def capture_event(event):
            events.append(event)
        
        orchestrator = ChainOrchestrator(event_callback=capture_event)
        check = MockCheck("test_check")
        orchestrator.add_check(check, suite="network")
        
        await orchestrator.run({})
        
        event_types = [e.get("type") for e in events]
        assert "run_started" in event_types
        assert "phase_started" in event_types
        assert "check_started" in event_types
        assert "check_completed" in event_types
        assert "run_completed" in event_types

    @pytest.mark.asyncio
    async def test_stop_halts_execution(self, orchestrator):
        """Test stop() halts execution."""
        check1 = MockCheck("check1")
        check2 = MockCheck("check2")
        
        orchestrator.add_check(check1, suite="network")
        orchestrator.add_check(check2, suite="web")
        
        # Stop before running
        orchestrator.stop()
        
        await orchestrator.run({})
        
        # Should not have run
        assert not orchestrator.is_running


# ═══════════════════════════════════════════════════════════════════════════════
# Diagnostics Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDiagnostics:
    """Tests for diagnostic output."""

    def test_get_diagnostics(self, orchestrator):
        """Test diagnostics contain expected info."""
        check = MockCheck("test_check", produces=["data"])
        orchestrator.add_check(check, suite="network")
        
        diag = orchestrator.get_diagnostics()
        
        assert "suites" in diag
        assert "context_keys" in diag
        assert "dependency_graph" in diag
        assert "test_check" in diag["dependency_graph"]

    @pytest.mark.asyncio
    async def test_stats_updated(self, orchestrator):
        """Test stats are updated after run."""
        check = MockCheck("test_check")
        orchestrator.add_check(check, suite="network")
        
        await orchestrator.run({})
        
        assert orchestrator.checks_run > 0
        assert orchestrator.phases_completed > 0
