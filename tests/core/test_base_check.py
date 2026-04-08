"""
Tests for data models: Service, Observation, CheckCondition, Severity, CheckStatus.
"""

import pytest

from app.checks.base import (
    CheckCondition,
    CheckStatus,
    Observation,
    Service,
    Severity,
)

pytestmark = pytest.mark.unit

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
# Observation Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestObservation:
    """Tests for Observation dataclass."""

    def test_observation_creation(self):
        """Observation can be created with required fields."""
        f = Observation(
            id="F-001",
            title="Test Observation",
            description="A test",
            severity="high",
            evidence="some evidence",
        )
        assert f.id == "F-001"
        assert f.title == "Test Observation"
        assert f.severity == "high"
        assert f.target is None
        assert f.references == []

    def test_observation_to_dict(self, sample_service):
        """Observation serializes to dict correctly."""
        f = Observation(
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
# Severity Enum Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_member_count(self):
        """Severity enum has exactly 5 levels."""
        assert len(Severity) == 5

    def test_severity_members_are_lowercase(self):
        """All severity values are lowercase strings matching their member names."""
        for member in Severity:
            assert member.value == member.name.lower()

    def test_severity_constructible_from_value(self):
        """Severity members can be looked up by their string value."""
        assert Severity("info") is Severity.INFO
        assert Severity("critical") is Severity.CRITICAL

    def test_severity_rejects_unknown_value(self):
        """Severity raises ValueError for unknown strings."""
        with pytest.raises(ValueError):
            Severity("super_critical")


# ═══════════════════════════════════════════════════════════════════════════════
# CheckStatus Enum Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckStatus:
    """Tests for CheckStatus enum."""

    def test_status_member_count(self):
        """CheckStatus enum has exactly 5 states."""
        assert len(CheckStatus) == 5

    def test_status_members_are_lowercase(self):
        """All status values are lowercase strings matching their member names."""
        for member in CheckStatus:
            assert member.value == member.name.lower()

    def test_status_constructible_from_value(self):
        """CheckStatus members can be looked up by their string value."""
        assert CheckStatus("pending") is CheckStatus.PENDING
        assert CheckStatus("skipped") is CheckStatus.SKIPPED

    def test_status_rejects_unknown_value(self):
        """CheckStatus raises ValueError for unknown strings."""
        with pytest.raises(ValueError):
            CheckStatus("cancelled")
