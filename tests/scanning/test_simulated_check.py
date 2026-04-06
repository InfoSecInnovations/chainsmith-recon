"""Tests for SimulationBehavior, SimulationConfig, SimulatedCheck basic init and execution."""

from pathlib import Path

import pytest

from app.checks.base import CheckStatus
from app.checks.simulator.simulated_check import (
    VALID_FAILURE_MODES,
    SimulatedCheck,
    SimulationBehavior,
    SimulationConfig,
)

pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# SimulationBehavior Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSimulationBehavior:
    """Tests for SimulationBehavior dataclass."""

    def test_default_values(self):
        """Defaults are sensible."""
        behavior = SimulationBehavior()

        assert behavior.latency_ms == 0
        assert behavior.failure_mode == "none"
        assert behavior.failure_message == "Simulated failure"

    def test_valid_failure_modes(self):
        """All valid failure modes are accepted."""
        for mode in VALID_FAILURE_MODES:
            behavior = SimulationBehavior(failure_mode=mode)
            assert behavior.failure_mode == mode

    def test_invalid_failure_mode_raises(self):
        """Invalid failure mode raises ValueError."""
        with pytest.raises(ValueError, match="Invalid failure_mode"):
            SimulationBehavior(failure_mode="invalid")

    def test_custom_latency(self):
        """Custom latency is stored."""
        behavior = SimulationBehavior(latency_ms=500)
        assert behavior.latency_ms == 500

    def test_custom_failure_message(self):
        """Custom failure message is stored."""
        behavior = SimulationBehavior(
            failure_mode="exception",
            failure_message="Custom error",
        )
        assert behavior.failure_message == "Custom error"


# ═══════════════════════════════════════════════════════════════════════════════
# SimulationConfig Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSimulationConfig:
    """Tests for SimulationConfig parsing."""

    def test_from_dict_minimal(self):
        """Minimal valid config is parsed."""
        data = {
            "suite": "network",
            "emulates": "dns_enumeration",
            "target": "example.local",
            "disposition": "hosts_found",
        }

        config = SimulationConfig.from_dict(data)

        assert config.suite == "network"
        assert config.emulates == "dns_enumeration"
        assert config.target == "example.local"
        assert config.disposition == "hosts_found"
        assert config.output == {}
        assert config.behavior.failure_mode == "none"

    def test_from_dict_with_output(self):
        """Config with output section is parsed."""
        data = {
            "suite": "network",
            "emulates": "dns_enumeration",
            "target": "example.local",
            "disposition": "hosts_found",
            "output": {"hosts": [{"name": "www.example.local", "ip": "10.0.0.1", "port": 80}]},
        }

        config = SimulationConfig.from_dict(data)

        assert "hosts" in config.output
        assert len(config.output["hosts"]) == 1

    def test_from_dict_with_behavior(self):
        """Config with behavior section is parsed."""
        data = {
            "suite": "network",
            "emulates": "dns_enumeration",
            "target": "example.local",
            "disposition": "error",
            "behavior": {
                "latency_ms": 200,
                "failure_mode": "exception",
                "failure_message": "Test failure",
            },
        }

        config = SimulationConfig.from_dict(data)

        assert config.behavior.latency_ms == 200
        assert config.behavior.failure_mode == "exception"
        assert config.behavior.failure_message == "Test failure"

    def test_from_dict_missing_required_field(self):
        """Missing required field raises ValueError."""
        data = {
            "suite": "network",
            "emulates": "dns_enumeration",
            # missing target and disposition
        }

        with pytest.raises(ValueError, match="missing required field"):
            SimulationConfig.from_dict(data)

    def test_from_yaml_valid_file(self, tmp_path: Path):
        """Config loads from valid YAML file."""
        yaml_content = """
suite: web
emulates: header_analysis
target: example.com
disposition: headers_found
output:
  headers:
    X-Custom: value
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content)

        config = SimulationConfig.from_yaml(yaml_file)

        assert config.suite == "web"
        assert config.emulates == "header_analysis"
        assert config.output["headers"]["X-Custom"] == "value"

    def test_from_yaml_file_not_found(self, tmp_path: Path):
        """Missing file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            SimulationConfig.from_yaml(tmp_path / "nonexistent.yaml")

    def test_from_yaml_invalid_yaml(self, tmp_path: Path):
        """Non-mapping YAML raises ValueError."""
        yaml_file = tmp_path / "invalid.yaml"
        yaml_file.write_text("- just\n- a\n- list")

        with pytest.raises(ValueError, match="must be a YAML mapping"):
            SimulationConfig.from_yaml(yaml_file)


# ═══════════════════════════════════════════════════════════════════════════════
# SimulatedCheck Basic Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSimulatedCheckBasic:
    """Tests for SimulatedCheck initialization and metadata."""

    @pytest.fixture
    def minimal_config(self) -> SimulationConfig:
        """Minimal valid config."""
        return SimulationConfig(
            suite="test",
            emulates="test_check",
            target="test.local",
            disposition="success",
            output={"key": "value"},
        )

    def test_initialization(self, minimal_config: SimulationConfig):
        """Check initializes with config values."""
        check = SimulatedCheck(minimal_config)

        assert check.name == "test_check"
        assert check.suite == "test"
        assert check.conditions == []
        assert check.timeout_seconds == 60.0

    def test_display_name(self, minimal_config: SimulationConfig):
        """display_name includes (simulated) suffix."""
        check = SimulatedCheck(minimal_config)

        assert check.display_name == "test_check (simulated)"

    def test_to_dict_includes_simulation_metadata(self, minimal_config: SimulationConfig):
        """to_dict includes simulation-specific fields."""
        check = SimulatedCheck(minimal_config)
        d = check.to_dict()

        assert d["simulated"] is True
        assert d["emulates"] == "test_check"
        assert d["suite"] == "test"
        assert d["disposition"] == "success"


# ═══════════════════════════════════════════════════════════════════════════════
# SimulatedCheck Execution Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSimulatedCheckExecution:
    """Tests for SimulatedCheck run behavior."""

    async def test_run_normal_mode(self):
        """Normal mode returns configured output."""
        config = SimulationConfig(
            suite="test",
            emulates="test_check",
            target="test.local",
            disposition="success",
            output={"custom_key": "custom_value"},
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        assert result.success is True
        assert result.outputs["custom_key"] == "custom_value"
        assert result.outputs["_simulated"] is True
        assert result.outputs["disposition"] == "success"

    async def test_run_with_latency(self):
        """Latency adds delay to execution."""
        config = SimulationConfig(
            suite="test",
            emulates="test_check",
            target="test.local",
            disposition="success",
            output={},
            behavior=SimulationBehavior(latency_ms=100),
        )
        check = SimulatedCheck(config)

        import time

        start = time.time()
        await check.run({})
        elapsed = time.time() - start

        assert elapsed >= 0.09  # At least 90ms

    async def test_run_exception_mode(self):
        """Exception mode raises RuntimeError."""
        config = SimulationConfig(
            suite="test",
            emulates="test_check",
            target="test.local",
            disposition="error",
            output={},
            behavior=SimulationBehavior(
                failure_mode="exception",
                failure_message="Test exception",
            ),
        )
        check = SimulatedCheck(config)

        with pytest.raises(RuntimeError, match="Test exception"):
            await check.run({})

    async def test_run_timeout_mode(self):
        """Timeout mode sleeps indefinitely (test with short timeout)."""
        config = SimulationConfig(
            suite="test",
            emulates="test_check",
            target="test.local",
            disposition="timeout",
            output={},
            behavior=SimulationBehavior(failure_mode="timeout"),
        )
        check = SimulatedCheck(config)
        check.timeout_seconds = 0.1  # Override for test

        # Use execute() which handles timeout
        result = await check.execute({})

        assert check.status == CheckStatus.FAILED
        assert any("timed out" in e for e in result.errors)

    async def test_run_malformed_mode(self):
        """Malformed mode returns output with malformed flag."""
        config = SimulationConfig(
            suite="test",
            emulates="test_check",
            target="test.local",
            disposition="malformed",
            output={"bad": "data"},
            behavior=SimulationBehavior(failure_mode="malformed"),
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        assert result.outputs["_simulated"] is True
        assert result.outputs["_malformed"] is True
        assert result.outputs["bad"] == "data"
