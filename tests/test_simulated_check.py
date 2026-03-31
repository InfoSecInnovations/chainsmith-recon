"""
Tests for app/checks/simulator/simulated_check.py

Covers:
- SimulationBehavior dataclass and validation
- SimulationConfig parsing from dict and YAML
- SimulatedCheck execution (normal, latency, failure modes)
- Service and Finding generation from hosts output
- Factory functions (load_simulated_check, load_simulated_checks_from_dir)
- Metadata and serialization
"""

import asyncio
from pathlib import Path
from typing import Any

import pytest

from app.checks.base import CheckResult, CheckStatus, Service
from app.checks.simulator.simulated_check import (
    SimulatedCheck,
    SimulationBehavior,
    SimulationConfig,
    load_simulated_check,
    load_simulated_checks_from_dir,
    VALID_FAILURE_MODES,
)


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
            "output": {
                "hosts": [
                    {"name": "www.example.local", "ip": "10.0.0.1", "port": 80}
                ]
            },
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


# ═══════════════════════════════════════════════════════════════════════════════
# SimulatedCheck Host/Service Generation Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSimulatedCheckHostGeneration:
    """Tests for service and finding generation from hosts output."""

    async def test_hosts_generate_services(self):
        """Hosts in output generate Service objects."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={
                "hosts": [
                    {"name": "www.example.local", "ip": "10.0.0.1", "port": 80},
                    {"name": "api.example.local", "ip": "10.0.0.2", "port": 8080},
                ]
            },
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        assert len(result.services) == 2
        assert result.services[0].host == "www.example.local"
        assert result.services[0].port == 80
        assert result.services[1].host == "api.example.local"
        assert result.services[1].port == 8080

    async def test_hosts_generate_findings(self):
        """Hosts in output generate Finding objects."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={
                "hosts": [
                    {"name": "www.example.local", "ip": "10.0.0.1", "port": 80}
                ]
            },
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert "www.example.local" in finding.title
        assert finding.severity == "info"
        assert finding.check_name == "dns_enumeration"

    async def test_host_service_metadata(self):
        """Service metadata includes IP and simulated flag."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={
                "hosts": [
                    {"name": "www.example.local", "ip": "192.168.1.1", "port": 443}
                ]
            },
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        svc = result.services[0]
        assert svc.metadata["ip"] == "192.168.1.1"
        assert svc.metadata["simulated"] is True

    async def test_host_with_scheme(self):
        """Host with custom scheme is respected."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={
                "hosts": [
                    {"name": "secure.example.local", "ip": "10.0.0.1", "port": 443, "scheme": "https"}
                ]
            },
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        svc = result.services[0]
        assert svc.scheme == "https"
        assert svc.url == "https://secure.example.local:443"

    async def test_host_with_type(self):
        """Host with service type is respected."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={
                "hosts": [
                    {"name": "chat.example.local", "ip": "10.0.0.1", "port": 8080, "type": "ai"}
                ]
            },
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        svc = result.services[0]
        assert svc.service_type == "ai"

    async def test_services_added_to_outputs(self):
        """Services are also available in outputs dict."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={
                "hosts": [
                    {"name": "www.example.local", "ip": "10.0.0.1", "port": 80}
                ]
            },
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        assert "services" in result.outputs
        assert len(result.outputs["services"]) == 1

    async def test_no_hosts_no_services(self):
        """Without hosts in output, no services are generated."""
        config = SimulationConfig(
            suite="web",
            emulates="header_check",
            target="example.local",
            disposition="headers_found",
            output={"headers": {"X-Custom": "value"}},
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        assert result.services == []
        assert result.findings == []


class TestSimulatedCheckDnsFormat:
    """Tests for the new DNS simulation format (target_hosts + dns_records)."""

    async def test_dns_format_generates_findings_not_services(self):
        """DNS format (target_hosts + dns_records) creates findings but no services."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={
                "target_hosts": ["www.example.local", "api.example.local"],
                "dns_records": {
                    "www.example.local": "10.0.1.10",
                    "api.example.local": "10.0.1.11",
                },
            },
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        # DNS should not create services
        assert result.services == []
        # But should create findings
        assert len(result.findings) == 2

    async def test_dns_format_finding_content(self):
        """DNS findings have correct content and no target/target_url."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={
                "target_hosts": ["www.example.local"],
                "dns_records": {
                    "www.example.local": "192.168.1.1",
                },
            },
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        finding = result.findings[0]
        assert "www.example.local" in finding.title
        assert "192.168.1.1" in finding.description
        assert finding.target is None
        assert finding.target_url is None
        assert finding.check_name == "dns_enumeration"

    async def test_dns_format_outputs_preserved(self):
        """DNS format preserves target_hosts and dns_records in outputs."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={
                "target_hosts": ["www.example.local", "api.example.local"],
                "dns_records": {
                    "www.example.local": "10.0.1.10",
                    "api.example.local": "10.0.1.11",
                },
            },
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        assert "target_hosts" in result.outputs
        assert "dns_records" in result.outputs
        assert "www.example.local" in result.outputs["target_hosts"]
        assert result.outputs["dns_records"]["www.example.local"] == "10.0.1.10"
        # No services key since DNS doesn't create services
        assert "services" not in result.outputs

    async def test_legacy_hosts_format_still_works(self):
        """Legacy hosts format (for non-DNS checks) still creates services."""
        config = SimulationConfig(
            suite="network",
            emulates="port_scan",  # Not dns_enumeration
            target="example.local",
            disposition="ports_found",
            output={
                "hosts": [
                    {"host": "www.example.local", "ip": "10.0.1.10", "port": 8080}
                ]
            },
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        # Legacy format creates services
        assert len(result.services) == 1
        assert result.services[0].host == "www.example.local"
        assert result.services[0].port == 8080


# ═══════════════════════════════════════════════════════════════════════════════
# Factory Function Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFactoryFunctions:
    """Tests for load_simulated_check and load_simulated_checks_from_dir."""

    def test_load_simulated_check_valid(self, tmp_path: Path):
        """load_simulated_check returns configured SimulatedCheck."""
        yaml_content = """
suite: network
emulates: dns_enumeration
target: test.local
disposition: success
output:
  key: value
"""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(yaml_content)

        check = load_simulated_check(yaml_file)

        assert isinstance(check, SimulatedCheck)
        assert check.name == "dns_enumeration"
        assert check.suite == "network"

    def test_load_simulated_check_file_not_found(self, tmp_path: Path):
        """load_simulated_check raises for missing file."""
        with pytest.raises(FileNotFoundError):
            load_simulated_check(tmp_path / "missing.yaml")

    def test_load_simulated_check_invalid_config(self, tmp_path: Path):
        """load_simulated_check raises for invalid config."""
        yaml_file = tmp_path / "invalid.yaml"
        yaml_file.write_text("suite: network\n")  # Missing required fields

        with pytest.raises(ValueError):
            load_simulated_check(yaml_file)

    def test_load_simulated_checks_from_dir(self, tmp_path: Path):
        """load_simulated_checks_from_dir loads all YAML files."""
        # Create directory structure
        network_dir = tmp_path / "network"
        network_dir.mkdir()

        (network_dir / "check1.yaml").write_text("""
suite: network
emulates: check1
target: test.local
disposition: success
output: {}
""")
        (network_dir / "check2.yaml").write_text("""
suite: network
emulates: check2
target: test.local
disposition: success
output: {}
""")

        checks = load_simulated_checks_from_dir(tmp_path)

        assert len(checks) == 2
        names = {c.name for c in checks}
        assert "check1" in names
        assert "check2" in names

    def test_load_simulated_checks_from_dir_with_suite_filter(self, tmp_path: Path):
        """Suite filter restricts which directory is searched."""
        # Create two suite directories
        network_dir = tmp_path / "network"
        web_dir = tmp_path / "web"
        network_dir.mkdir()
        web_dir.mkdir()

        (network_dir / "net.yaml").write_text("""
suite: network
emulates: net_check
target: test.local
disposition: success
output: {}
""")
        (web_dir / "web.yaml").write_text("""
suite: web
emulates: web_check
target: test.local
disposition: success
output: {}
""")

        checks = load_simulated_checks_from_dir(tmp_path, suite="network")

        assert len(checks) == 1
        assert checks[0].name == "net_check"

    def test_load_simulated_checks_skips_invalid(self, tmp_path: Path, caplog):
        """Invalid configs are skipped with warning."""
        (tmp_path / "valid.yaml").write_text("""
suite: test
emulates: valid
target: test.local
disposition: success
output: {}
""")
        (tmp_path / "invalid.yaml").write_text("not: valid: yaml: config")

        import logging

        with caplog.at_level(logging.WARNING):
            checks = load_simulated_checks_from_dir(tmp_path)

        assert len(checks) == 1
        assert checks[0].name == "valid"

    def test_load_simulated_checks_empty_dir(self, tmp_path: Path):
        """Empty directory returns empty list."""
        checks = load_simulated_checks_from_dir(tmp_path)
        assert checks == []


# ═══════════════════════════════════════════════════════════════════════════════
# Integration with Real Simulation Files
# ═══════════════════════════════════════════════════════════════════════════════


class TestRealSimulationFiles:
    """Tests using actual simulation files from the project."""

    def test_load_dns_success(self, simulations_dir: Path):
        """Load actual dns_success.yaml file."""
        yaml_file = simulations_dir / "network" / "dns_success.yaml"

        if not yaml_file.exists():
            pytest.skip("dns_success.yaml not found")

        check = load_simulated_check(yaml_file)

        assert check.name == "dns_enumeration"
        assert check.suite == "network"

    async def test_run_dns_success(self, simulations_dir: Path):
        """Run actual dns_success simulation."""
        yaml_file = simulations_dir / "network" / "dns_success.yaml"

        if not yaml_file.exists():
            pytest.skip("dns_success.yaml not found")

        check = load_simulated_check(yaml_file)
        result = await check.run({})

        assert result.success is True
        assert len(result.services) > 0
        assert len(result.findings) > 0

    def test_load_dns_exception(self, simulations_dir: Path):
        """Load actual dns_exception.yaml file."""
        yaml_file = simulations_dir / "network" / "dns_exception.yaml"

        if not yaml_file.exists():
            pytest.skip("dns_exception.yaml not found")

        check = load_simulated_check(yaml_file)

        assert check._config.behavior.failure_mode == "exception"

    async def test_run_dns_exception(self, simulations_dir: Path):
        """Run actual dns_exception simulation."""
        yaml_file = simulations_dir / "network" / "dns_exception.yaml"

        if not yaml_file.exists():
            pytest.skip("dns_exception.yaml not found")

        check = load_simulated_check(yaml_file)

        with pytest.raises(RuntimeError):
            await check.run({})

    def test_load_all_network_simulations(self, simulations_dir: Path):
        """Load all network simulations without error."""
        network_dir = simulations_dir / "network"

        if not network_dir.exists():
            pytest.skip("network simulations directory not found")

        checks = load_simulated_checks_from_dir(simulations_dir, suite="network")

        # Should load at least some checks
        assert len(checks) > 0

        # All should be SimulatedCheck instances
        for check in checks:
            assert isinstance(check, SimulatedCheck)
            assert check.suite == "network"
