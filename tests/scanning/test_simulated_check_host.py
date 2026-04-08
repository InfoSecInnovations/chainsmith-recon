"""Tests for SimulatedCheck host generation, DNS format, factory functions, and real simulation files."""

from pathlib import Path

import pytest

from app.checks.simulator.simulated_check import (
    SimulatedCheck,
    SimulationConfig,
    load_simulated_check,
    load_simulated_checks_from_dir,
)

pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# SimulatedCheck Host/Service Generation Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestSimulatedCheckHostGeneration:
    """Tests for service and observation generation from hosts output."""

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

    async def test_hosts_generate_observations(self):
        """Hosts in output generate Observation objects."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={"hosts": [{"name": "www.example.local", "ip": "10.0.0.1", "port": 80}]},
        )
        check = SimulatedCheck(config)

        result = await check.run({})

        assert len(result.observations) == 1
        observation = result.observations[0]
        assert "www.example.local" in observation.title
        assert observation.severity == "info"
        assert observation.check_name == "dns_enumeration"

    async def test_host_service_metadata(self):
        """Service metadata includes IP and simulated flag."""
        config = SimulationConfig(
            suite="network",
            emulates="dns_enumeration",
            target="example.local",
            disposition="hosts_found",
            output={"hosts": [{"name": "www.example.local", "ip": "192.168.1.1", "port": 443}]},
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
                    {
                        "name": "secure.example.local",
                        "ip": "10.0.0.1",
                        "port": 443,
                        "scheme": "https",
                    }
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
            output={"hosts": [{"name": "www.example.local", "ip": "10.0.0.1", "port": 80}]},
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
        assert result.observations == []


class TestSimulatedCheckDnsFormat:
    """Tests for the new DNS simulation format (target_hosts + dns_records)."""

    async def test_dns_format_generates_observations_not_services(self):
        """DNS format (target_hosts + dns_records) creates observations but no services."""
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
        # But should create observations
        assert len(result.observations) == 2

    async def test_dns_format_observation_content(self):
        """DNS observations have correct content and no target/target_url."""
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

        observation = result.observations[0]
        assert "www.example.local" in observation.title
        assert "192.168.1.1" in observation.description
        assert observation.target is None
        assert observation.target_url is None
        assert observation.check_name == "dns_enumeration"

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
            output={"hosts": [{"host": "www.example.local", "ip": "10.0.1.10", "port": 8080}]},
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
        assert len(result.services) >= 1, "DNS success should discover at least 1 service"
        assert len(result.observations) >= 1, "DNS success should produce at least 1 observation"
        # Verify observations have expected check_name from the simulation
        for obs in result.observations:
            assert obs.check_name == "dns_enumeration"

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

        # Should load at least 2 checks (dns_success, dns_exception at minimum)
        assert len(checks) >= 2, f"Expected at least 2 network simulations, got {len(checks)}"

        # All should be SimulatedCheck instances with correct suite
        names = set()
        for check in checks:
            assert isinstance(check, SimulatedCheck)
            assert check.suite == "network"
            names.add(check.name)

        # Verify known simulation names are present
        assert "dns_enumeration" in names, "dns_enumeration simulation should be loaded"
