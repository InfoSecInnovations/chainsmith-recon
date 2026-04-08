"""
Tests for BaseCheck execution and ServiceIteratingCheck iteration.
"""

import asyncio
from typing import Any

import pytest

from app.checks.base import (
    BaseCheck,
    CheckCondition,
    CheckResult,
    CheckStatus,
    Observation,
    Service,
    ServiceIteratingCheck,
)

pytestmark = pytest.mark.unit


class ConcreteCheck(BaseCheck):
    """Concrete implementation for testing BaseCheck."""

    name = "concrete_check"
    description = "A concrete check for testing"
    produces = ["output_key"]
    timeout_seconds = 1.0

    def __init__(self, return_value: Any = None, should_fail: bool = False, delay: float = 0):
        super().__init__()
        self.return_value = return_value
        self.should_fail = should_fail
        self.delay = delay

    async def run(self, context: dict[str, Any]) -> CheckResult:
        if self.delay > 0:
            await asyncio.sleep(self.delay)

        if self.should_fail:
            raise RuntimeError("Intentional failure")

        return CheckResult(
            success=True,
            outputs={"output_key": self.return_value or "result"},
        )


class TestBaseCheck:
    """Tests for BaseCheck execution."""

    async def test_execute_success(self):
        """Successful check execution sets status and result."""
        check = ConcreteCheck(return_value="test_output")
        result = await check.execute({})

        assert result.success is True
        assert result.outputs["output_key"] == "test_output"
        assert result.check_name == "concrete_check"
        assert check.status == CheckStatus.COMPLETED
        assert check.result is result
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.duration_ms is not None
        assert result.duration_ms >= 0

    async def test_execute_failure(self):
        """Failed check sets FAILED status and records error."""
        check = ConcreteCheck(should_fail=True)
        result = await check.execute({})

        assert result.success is False
        assert check.status == CheckStatus.FAILED
        assert len(result.errors) == 1
        assert "Intentional failure" in result.errors[0]

    async def test_execute_timeout(self):
        """Check that exceeds timeout is handled."""
        check = ConcreteCheck(delay=2.0)  # timeout_seconds = 1.0
        result = await check.execute({})

        assert result.success is False
        assert check.status == CheckStatus.FAILED
        assert any("timed out" in e for e in result.errors)

    async def test_observations_tagged_with_check_name(self, sample_service):
        """Observations are tagged with check name after execution."""

        class ObservationCheck(BaseCheck):
            name = "observation_check"

            async def run(self, context):
                return CheckResult(
                    success=True,
                    observations=[
                        Observation(
                            id="",
                            title="Test",
                            description="Test",
                            severity="info",
                            evidence="Test",
                        )
                    ],
                )

        check = ObservationCheck()
        result = await check.execute({})

        assert len(result.observations) == 1
        assert result.observations[0].check_name == "observation_check"

    def test_can_run_no_conditions(self):
        """Check with no conditions can always run."""
        check = ConcreteCheck()
        check.conditions = []
        assert check.can_run({}) is True
        assert check.can_run({"anything": "here"}) is True

    def test_can_run_with_conditions(self):
        """Check respects conditions."""
        check = ConcreteCheck()
        check.conditions = [CheckCondition("services", "truthy")]

        assert check.can_run({}) is False
        assert check.can_run({"services": []}) is False
        assert check.can_run({"services": ["svc1"]}) is True

    def test_get_missing_conditions(self):
        """get_missing_conditions returns unsatisfied conditions."""
        check = ConcreteCheck()
        check.conditions = [
            CheckCondition("services", "truthy"),
            CheckCondition("hosts", "exists"),
        ]

        missing = check.get_missing_conditions({"services": ["svc"]})
        assert len(missing) == 1
        assert "hosts" in missing[0]

    def test_filter_services_no_filter(self, sample_services):
        """Without service_types, all services pass."""
        check = ConcreteCheck()
        check.service_types = []
        filtered = check.filter_services(sample_services)
        assert len(filtered) == len(sample_services)

    def test_filter_services_with_filter(self, sample_services):
        """With service_types, only matching services pass."""
        check = ConcreteCheck()
        check.service_types = ["ai"]
        filtered = check.filter_services(sample_services)
        assert len(filtered) == 1
        assert filtered[0].service_type == "ai"

    def test_scope_validator_default(self):
        """Without scope validator, all URLs are in scope."""
        check = ConcreteCheck()
        assert check.is_in_scope("http://anything.com") is True

    def test_scope_validator_custom(self):
        """Scope validator is called correctly."""
        check = ConcreteCheck()
        check.set_scope_validator(lambda url: "allowed" in url)

        assert check.is_in_scope("http://allowed.com") is True
        assert check.is_in_scope("http://blocked.com") is False

    def test_create_observation_helper(self, sample_service):
        """create_observation helper creates properly formatted observation."""
        check = ConcreteCheck()
        observation = check.create_observation(
            title="Test Issue",
            description="A test issue",
            severity="high",
            evidence="evidence here",
            target=sample_service,
            references=["REF-001"],
        )

        assert observation.id == ""  # Assigned by runner
        assert observation.title == "Test Issue"
        assert observation.severity == "high"
        assert observation.check_name == "concrete_check"
        assert observation.target_url == sample_service.url
        assert "REF-001" in observation.references

    def test_to_dict_serialization(self):
        """to_dict returns complete check metadata."""
        check = ConcreteCheck()
        check.reason = "Test reason"
        check.references = ["REF-001"]
        check.techniques = ["T1234"]

        d = check.to_dict()
        assert d["name"] == "concrete_check"
        assert d["description"] == "A concrete check for testing"
        assert d["produces"] == ["output_key"]
        assert d["timeout_seconds"] == 1.0
        assert d["educational"]["reason"] == "Test reason"
        assert "REF-001" in d["educational"]["references"]


class ConcreteIteratingCheck(ServiceIteratingCheck):
    """Concrete implementation for testing ServiceIteratingCheck."""

    name = "iterating_check"
    description = "Iterates over services"
    service_types = []  # All services
    delay_between_targets = 0  # Fast for tests

    def __init__(self):
        super().__init__()
        self.checked_services: list[Service] = []

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        self.checked_services.append(service)
        return CheckResult(
            success=True,
            observations=[
                Observation(
                    id="",
                    title=f"Found on {service.host}",
                    description="Test observation",
                    severity="info",
                    evidence="test",
                    target=service,
                )
            ],
        )


class TestServiceIteratingCheck:
    """Tests for ServiceIteratingCheck."""

    async def test_iterates_over_all_services(self, sample_services):
        """Check iterates over all services in context."""
        check = ConcreteIteratingCheck()
        context = {"services": sample_services}

        result = await check.run(context)

        assert result.success is True
        assert len(check.checked_services) == 2
        assert result.targets_checked == 2

    async def test_no_services_error(self):
        """Error when no services in context."""
        check = ConcreteIteratingCheck()
        result = await check.run({})

        assert any("No services" in e for e in result.errors)

    async def test_filters_by_service_type(self, sample_services):
        """Only services matching service_types are checked."""
        check = ConcreteIteratingCheck()
        check.service_types = ["ai"]
        context = {"services": sample_services}

        await check.run(context)

        assert len(check.checked_services) == 1
        assert check.checked_services[0].service_type == "ai"

    async def test_no_matching_services_error(self, sample_services):
        """Error when no services match filter."""
        check = ConcreteIteratingCheck()
        check.service_types = ["nonexistent"]
        context = {"services": sample_services}

        result = await check.run(context)

        assert any("No services match" in e for e in result.errors)

    async def test_scope_validation_filters_services(self, sample_services):
        """Out-of-scope services are skipped."""
        check = ConcreteIteratingCheck()
        check.set_scope_validator(lambda url: "ai.test" in url)
        context = {"services": sample_services}

        result = await check.run(context)

        assert len(check.checked_services) == 1
        assert "ai.test" in check.checked_services[0].url
        assert any("Out of scope" in e for e in result.errors)
        assert result.targets_failed == 1

    async def test_handles_service_dicts(self, sample_service):
        """Services can be passed as dicts and are converted."""
        check = ConcreteIteratingCheck()
        context = {"services": [sample_service.to_dict()]}

        await check.run(context)

        assert len(check.checked_services) == 1
        assert isinstance(check.checked_services[0], Service)

    async def test_accumulates_observations(self, sample_services):
        """Observations from all services are accumulated."""
        check = ConcreteIteratingCheck()
        context = {"services": sample_services}

        result = await check.run(context)

        assert len(result.observations) == 2

    async def test_handles_per_service_exception(self, sample_services):
        """Exception in one service doesn't stop iteration."""

        class FailingIteratingCheck(ServiceIteratingCheck):
            name = "failing_iterating"
            service_types = []
            delay_between_targets = 0

            async def check_service(self, service, context):
                if "ai" in service.url:
                    raise RuntimeError("AI service failed")
                return CheckResult(success=True)

        check = FailingIteratingCheck()
        context = {"services": sample_services}

        result = await check.run(context)

        # Should still complete, with one failure recorded
        assert result.targets_failed == 1
        assert any("AI service failed" in e for e in result.errors)
