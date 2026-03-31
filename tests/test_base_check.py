"""
Tests for app/checks/base.py

Covers:
- Service dataclass
- Finding dataclass
- CheckResult dataclass
- CheckCondition evaluation
- BaseCheck execution, timeout, error handling
- ServiceIteratingCheck iteration, filtering, scope validation
"""

import asyncio
from typing import Any

import pytest

from app.checks.base import (
    BaseCheck,
    CheckCondition,
    CheckResult,
    CheckStatus,
    Finding,
    Service,
    ServiceIteratingCheck,
    Severity,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Service Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestService:
    """Tests for Service dataclass."""

    def test_service_creation_basic(self):
        """Service can be created with required fields."""
        svc = Service(url="http://test.local:8080", host="test.local", port=8080)
        assert svc.url == "http://test.local:8080"
        assert svc.host == "test.local"
        assert svc.port == 8080
        assert svc.scheme == "http"
        assert svc.service_type == "unknown"
        assert svc.metadata == {}

    def test_service_url_generation_when_empty(self):
        """URL is auto-generated from components if empty."""
        svc = Service(url="", host="example.com", port=443, scheme="https")
        assert svc.url == "https://example.com:443"

    def test_service_with_path(self):
        """with_path appends path correctly."""
        svc = Service(url="http://test.local:8080", host="test.local", port=8080)

        # Path with leading slash
        assert svc.with_path("/api/v1") == "http://test.local:8080/api/v1"

        # Path without leading slash
        assert svc.with_path("api/v1") == "http://test.local:8080/api/v1"

        # Trailing slash on URL is handled
        svc2 = Service(url="http://test.local:8080/", host="test.local", port=8080)
        assert svc2.with_path("/api") == "http://test.local:8080/api"

    def test_service_to_dict(self):
        """Service serializes to dict correctly."""
        svc = Service(
            url="http://test.local:8080",
            host="test.local",
            port=8080,
            scheme="http",
            service_type="ai",
            metadata={"key": "value"},
        )
        d = svc.to_dict()
        assert d["url"] == "http://test.local:8080"
        assert d["host"] == "test.local"
        assert d["port"] == 8080
        assert d["scheme"] == "http"
        assert d["service_type"] == "ai"
        assert d["metadata"] == {"key": "value"}

    def test_service_from_dict(self):
        """Service can be deserialized from dict."""
        d = {
            "url": "http://test.local:8080",
            "host": "test.local",
            "port": 8080,
            "scheme": "http",
            "service_type": "api",
            "metadata": {"discovered": True},
        }
        svc = Service.from_dict(d)
        assert svc.url == "http://test.local:8080"
        assert svc.host == "test.local"
        assert svc.port == 8080
        assert svc.service_type == "api"
        assert svc.metadata == {"discovered": True}

    def test_service_from_dict_with_defaults(self):
        """Service.from_dict handles missing optional fields."""
        d = {"url": "http://minimal.local", "host": "minimal.local", "port": 80}
        svc = Service.from_dict(d)
        assert svc.scheme == "http"
        assert svc.service_type == "unknown"
        assert svc.metadata == {}


# ═══════════════════════════════════════════════════════════════════════════════
# Finding Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Finding can be created with required fields."""
        f = Finding(
            id="F-001",
            title="Test Finding",
            description="A test",
            severity="high",
            evidence="some evidence",
        )
        assert f.id == "F-001"
        assert f.title == "Test Finding"
        assert f.severity == "high"
        assert f.target is None
        assert f.references == []

    def test_finding_to_dict(self, sample_service):
        """Finding serializes to dict correctly."""
        f = Finding(
            id="F-002",
            title="Header Issue",
            description="Missing security headers",
            severity="medium",
            evidence="X-Frame-Options: missing",
            target=sample_service,
            target_url="http://test.local:8080/",
            check_name="header_analysis",
            references=["OWASP-A05"],
        )
        d = f.to_dict()
        assert d["id"] == "F-002"
        assert d["title"] == "Header Issue"
        assert d["severity"] == "medium"
        assert d["check_name"] == "header_analysis"
        assert d["target_url"] == "http://test.local:8080/"
        assert "OWASP-A05" in d["references"]


# ═══════════════════════════════════════════════════════════════════════════════
# CheckCondition Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckCondition:
    """Tests for CheckCondition evaluation."""

    def test_condition_exists_true(self):
        """'exists' returns True when key is present and not None."""
        cond = CheckCondition(output_name="services", operator="exists")
        assert cond.evaluate({"services": []}) is True
        assert cond.evaluate({"services": [1, 2, 3]}) is True

    def test_condition_exists_false(self):
        """'exists' returns False when key missing or None."""
        cond = CheckCondition(output_name="services", operator="exists")
        assert cond.evaluate({}) is False
        assert cond.evaluate({"services": None}) is False

    def test_condition_truthy_true(self):
        """'truthy' returns True for truthy values."""
        cond = CheckCondition(output_name="data", operator="truthy")
        assert cond.evaluate({"data": [1]}) is True
        assert cond.evaluate({"data": "yes"}) is True
        assert cond.evaluate({"data": 1}) is True

    def test_condition_truthy_false(self):
        """'truthy' returns False for falsy values."""
        cond = CheckCondition(output_name="data", operator="truthy")
        assert cond.evaluate({"data": []}) is False
        assert cond.evaluate({"data": ""}) is False
        assert cond.evaluate({"data": 0}) is False
        assert cond.evaluate({}) is False

    def test_condition_equals(self):
        """'equals' compares value exactly."""
        cond = CheckCondition(output_name="status", operator="equals", value="ready")
        assert cond.evaluate({"status": "ready"}) is True
        assert cond.evaluate({"status": "pending"}) is False
        assert cond.evaluate({}) is False

    def test_condition_contains_list(self):
        """'contains' checks membership in list."""
        cond = CheckCondition(output_name="tags", operator="contains", value="ai")
        assert cond.evaluate({"tags": ["web", "ai", "api"]}) is True
        assert cond.evaluate({"tags": ["web", "api"]}) is False

    def test_condition_contains_string(self):
        """'contains' checks substring in string."""
        cond = CheckCondition(output_name="response", operator="contains", value="error")
        assert cond.evaluate({"response": "an error occurred"}) is True
        assert cond.evaluate({"response": "success"}) is False

    def test_condition_contains_dict(self):
        """'contains' checks key in dict."""
        cond = CheckCondition(output_name="headers", operator="contains", value="X-Custom")
        assert cond.evaluate({"headers": {"X-Custom": "value"}}) is True
        assert cond.evaluate({"headers": {"Other": "value"}}) is False

    def test_condition_gte(self):
        """'gte' compares >= correctly."""
        cond = CheckCondition(output_name="count", operator="gte", value=5)
        assert cond.evaluate({"count": 10}) is True
        assert cond.evaluate({"count": 5}) is True
        assert cond.evaluate({"count": 4}) is False

    def test_condition_lte(self):
        """'lte' compares <= correctly."""
        cond = CheckCondition(output_name="count", operator="lte", value=5)
        assert cond.evaluate({"count": 3}) is True
        assert cond.evaluate({"count": 5}) is True
        assert cond.evaluate({"count": 6}) is False

    def test_condition_str_representation(self):
        """__str__ returns readable representation."""
        assert str(CheckCondition("services", "exists")) == "services exists"
        assert str(CheckCondition("data", "truthy")) == "data is truthy"
        assert str(CheckCondition("x", "equals", 5)) == "x equals 5"


# ═══════════════════════════════════════════════════════════════════════════════
# BaseCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


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

    async def test_findings_tagged_with_check_name(self, sample_service):
        """Findings are tagged with check name after execution."""

        class FindingCheck(BaseCheck):
            name = "finding_check"

            async def run(self, context):
                return CheckResult(
                    success=True,
                    findings=[
                        Finding(
                            id="",
                            title="Test",
                            description="Test",
                            severity="info",
                            evidence="Test",
                        )
                    ],
                )

        check = FindingCheck()
        result = await check.execute({})

        assert len(result.findings) == 1
        assert result.findings[0].check_name == "finding_check"

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

    def test_create_finding_helper(self, sample_service):
        """create_finding helper creates properly formatted finding."""
        check = ConcreteCheck()
        finding = check.create_finding(
            title="Test Issue",
            description="A test issue",
            severity="high",
            evidence="evidence here",
            target=sample_service,
            references=["REF-001"],
        )

        assert finding.id == ""  # Assigned by runner
        assert finding.title == "Test Issue"
        assert finding.severity == "high"
        assert finding.check_name == "concrete_check"
        assert finding.target_url == sample_service.url
        assert "REF-001" in finding.references

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


# ═══════════════════════════════════════════════════════════════════════════════
# ServiceIteratingCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


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
            findings=[
                Finding(
                    id="",
                    title=f"Found on {service.host}",
                    description="Test finding",
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

        result = await check.run(context)

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

        result = await check.run(context)

        assert len(check.checked_services) == 1
        assert isinstance(check.checked_services[0], Service)

    async def test_accumulates_findings(self, sample_services):
        """Findings from all services are accumulated."""
        check = ConcreteIteratingCheck()
        context = {"services": sample_services}

        result = await check.run(context)

        assert len(result.findings) == 2

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


# ═══════════════════════════════════════════════════════════════════════════════
# Severity Enum Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Severity enum has expected values."""
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"


# ═══════════════════════════════════════════════════════════════════════════════
# CheckStatus Enum Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckStatus:
    """Tests for CheckStatus enum."""

    def test_status_values(self):
        """CheckStatus enum has expected values."""
        assert CheckStatus.PENDING.value == "pending"
        assert CheckStatus.RUNNING.value == "running"
        assert CheckStatus.COMPLETED.value == "completed"
        assert CheckStatus.FAILED.value == "failed"
        assert CheckStatus.SKIPPED.value == "skipped"
