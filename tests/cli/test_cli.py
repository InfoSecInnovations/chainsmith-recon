"""
Tests for app/cli.py

Covers:
- CLI initialization and help
- scan command with various options
- list-checks command
- scenarios subcommands
- export command
- Output formatting (JSON, Markdown, SARIF)
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from app.cli import cli
from app.cli_formatters import (
    format_observation_terminal,
    observations_to_json,
    observations_to_markdown,
    observations_to_sarif,
)

pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def runner():
    """Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def sample_observation():
    """Sample observation dict for testing."""
    return {
        "id": "test-001",
        "title": "Test Observation",
        "description": "A test observation for unit tests",
        "severity": "medium",
        "evidence": "Some evidence here",
        "target_url": "http://example.com/api",
        "check_name": "test_check",
        "references": ["CWE-200"],
    }


@pytest.fixture
def sample_observations(sample_observation):
    """List of sample observation dicts."""
    return [
        sample_observation,
        {
            "id": "test-002",
            "title": "Critical Issue",
            "description": "A critical security issue",
            "severity": "critical",
            "evidence": "Critical evidence",
            "target_url": "http://example.com/admin",
            "check_name": "critical_check",
            "references": [],
        },
        {
            "id": "test-003",
            "title": "Info Observation",
            "description": "Informational",
            "severity": "info",
            "check_name": "info_check",
            "references": [],
        },
    ]


def _mock_client():
    """Create a mock ChainsmithClient."""
    client = MagicMock()
    client.health.return_value = {"status": "healthy"}
    return client


def _patch_client(client):
    """Patch _get_client to return a mock client, bypassing server startup."""
    return patch("app.cli._get_client", return_value=client)


# ═══════════════════════════════════════════════════════════════════════════════
# Output Formatting Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestOutputFormatting:
    """Tests for output formatting functions."""

    def test_format_observation_terminal(self, sample_observation):
        """format_observation_terminal produces colored output."""
        output = format_observation_terminal(sample_observation, verbose=False)
        assert "MEDIUM" in output
        assert "Test Observation" in output

    def test_format_observation_terminal_verbose(self, sample_observation):
        """format_observation_terminal verbose includes details."""
        output = format_observation_terminal(sample_observation, verbose=True)
        assert "Test Observation" in output
        assert "A test observation" in output
        assert "http://example.com/api" in output
        assert "test_check" in output

    def test_observations_to_json(self, sample_observations):
        """observations_to_json produces valid JSON."""
        output = observations_to_json(sample_observations)
        data = json.loads(output)

        assert len(data) == 3
        assert data[0]["title"] == "Test Observation"
        assert data[1]["severity"] == "critical"

    def test_observations_to_markdown(self, sample_observations):
        """observations_to_markdown produces Markdown report."""
        output = observations_to_markdown(sample_observations, "example.com")

        assert "# Chainsmith Recon Report" in output
        assert "**Target:** example.com" in output
        assert "## CRITICAL" in output
        assert "## MEDIUM" in output
        assert "## INFO" in output
        assert "Critical Issue" in output
        assert "Test Observation" in output

    def test_observations_to_sarif(self, sample_observations):
        """observations_to_sarif produces valid SARIF."""
        output = observations_to_sarif(sample_observations, "example.com")
        data = json.loads(output)

        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1

        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "Chainsmith Recon"
        assert len(run["results"]) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Command Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestCLIHelp:
    """Tests for CLI help and version."""

    def test_cli_help(self, runner):
        """CLI shows help."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Chainsmith Recon" in result.output
        assert "scan" in result.output
        assert "list-checks" in result.output
        assert "scenarios" in result.output

    def test_cli_version(self, runner):
        """CLI shows version."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.3.0" in result.output


class TestListChecksCommand:
    """Tests for list-checks command."""

    def test_list_checks_default(self, runner):
        """list-checks shows all checks."""
        client = _mock_client()
        client.get_checks.return_value = {
            "checks": [
                {"name": "dns_enumeration", "suite": "network", "description": "DNS enum"},
                {"name": "service_probe", "suite": "network", "description": "Service probe"},
                {"name": "header_analysis", "suite": "web", "description": "Header check"},
                {"name": "llm_endpoint_discovery", "suite": "ai", "description": "LLM discovery"},
            ],
            "simulated": False,
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["list-checks"])
            assert result.exit_code == 0
            assert "NETWORK" in result.output
            assert "WEB" in result.output
            assert "AI" in result.output
            assert "dns_enumeration" in result.output

    def test_list_checks_suite_filter(self, runner):
        """list-checks --suite filters by suite."""
        client = _mock_client()
        client.get_checks.return_value = {
            "checks": [
                {"name": "dns_enumeration", "suite": "network", "description": "DNS enum"},
                {"name": "service_probe", "suite": "network", "description": "Service probe"},
                {"name": "header_analysis", "suite": "web", "description": "Header check"},
            ],
            "simulated": False,
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["list-checks", "--suite", "network"])
            assert result.exit_code == 0
            assert "dns_enumeration" in result.output
            assert "service_probe" in result.output
            assert "header_analysis" not in result.output

    def test_list_checks_json(self, runner):
        """list-checks --json outputs JSON."""
        client = _mock_client()
        client.get_checks.return_value = {
            "checks": [
                {"name": "dns_enumeration", "suite": "network", "description": "DNS enum"},
            ],
            "simulated": False,
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["list-checks", "--json"])
            assert result.exit_code == 0

            data = json.loads(result.output)
            assert len(data) > 0
            assert "name" in data[0]

    def test_list_checks_verbose(self, runner):
        """list-checks --verbose shows details."""
        client = _mock_client()
        client.get_checks.return_value = {
            "checks": [
                {
                    "name": "dns_enumeration",
                    "suite": "network",
                    "description": "DNS enumeration",
                    "conditions": ["base_domain"],
                    "produces": ["subdomains"],
                },
            ],
            "simulated": False,
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["list-checks", "--verbose"])
            assert result.exit_code == 0
            assert "Requires:" in result.output or "Produces:" in result.output

    def test_list_checks_unknown_suite(self, runner):
        """list-checks with unknown suite shows error."""
        client = _mock_client()
        client.get_checks.return_value = {
            "checks": [
                {"name": "dns_enumeration", "suite": "network", "description": "DNS enum"},
            ],
            "simulated": False,
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["list-checks", "--suite", "unknown"])
            assert result.exit_code == 1
            assert "Unknown suite" in result.output


class TestScenariosCommand:
    """Tests for scenarios subcommands."""

    def test_scenarios_list(self, runner):
        """scenarios list shows available scenarios."""
        client = _mock_client()
        client.list_scenarios.return_value = {
            "scenarios": [
                {
                    "name": "fakobanko",
                    "description": "Test bank",
                    "version": "1.0",
                    "simulation_count": 10,
                }
            ],
            "active": None,
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["scenarios", "list"])
            assert result.exit_code == 0
            assert "fakobanko" in result.output

    def test_scenarios_list_empty(self, runner):
        """scenarios list shows message when no scenarios."""
        client = _mock_client()
        client.list_scenarios.return_value = {"scenarios": [], "active": None}

        with _patch_client(client):
            result = runner.invoke(cli, ["scenarios", "list"])
            assert result.exit_code == 0
            assert "No scenarios found" in result.output

    def test_scenarios_list_json(self, runner):
        """scenarios list --json outputs JSON."""
        client = _mock_client()
        client.list_scenarios.return_value = {
            "scenarios": [{"name": "test", "version": "1.0"}],
            "active": None,
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["scenarios", "list", "--json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert len(data) == 1

    def test_scenarios_info(self, runner):
        """scenarios info shows scenario details."""
        client = _mock_client()
        client.load_scenario.return_value = {
            "loaded": True,
            "scenario": {
                "name": "fakobanko",
                "description": "Fake bank scenario",
                "version": "1.0",
                "target": {
                    "pattern": "*.fakobanko.com",
                    "known_hosts": ["api.fakobanko.com"],
                    "ports": [80, 443],
                },
                "simulations": ["sim1", "sim2"],
                "expected_observations": [],
            },
            "simulation_count": 2,
        }
        client.clear_scenario.return_value = {"cleared": True}

        with _patch_client(client):
            result = runner.invoke(cli, ["scenarios", "info", "fakobanko"])
            assert result.exit_code == 0
            assert "fakobanko" in result.output
            assert "Fake bank scenario" in result.output


class TestScanCommand:
    """Tests for scan command."""

    def test_scan_help(self, runner):
        """scan --help shows options."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.output
        assert "--exclude" in result.output
        assert "--checks" in result.output
        assert "--suite" in result.output
        assert "--scenario" in result.output
        assert "--format" in result.output

    def test_scan_requires_target(self, runner):
        """scan requires target argument."""
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code != 0
        assert "Missing argument" in result.output

    def test_scan_basic(self, runner):
        """scan runs with basic target via API."""
        client = _mock_client()
        client.set_scope.return_value = {"status": "ok", "target": "example.com"}
        client.update_settings.return_value = {"status": "ok"}
        client.start_scan.return_value = {"status": "accepted"}
        client.poll_scan.return_value = {"status": "complete"}
        client.get_observations.return_value = {"total": 0, "observations": []}

        with _patch_client(client):
            result = runner.invoke(cli, ["scan", "example.com", "--quiet"])
            assert result.exit_code == 0

        client.set_scope.assert_called_once()
        client.start_scan.assert_called_once()

    def test_scan_with_suite(self, runner):
        """scan --suite passes suite filter to start_scan."""
        client = _mock_client()
        client.set_scope.return_value = {"status": "ok", "target": "example.com"}
        client.update_settings.return_value = {"status": "ok"}
        client.start_scan.return_value = {"status": "accepted"}
        client.poll_scan.return_value = {"status": "complete"}
        client.get_observations.return_value = {"total": 0, "observations": []}

        with _patch_client(client):
            result = runner.invoke(cli, ["scan", "example.com", "--suite", "network", "--quiet"])
            assert result.exit_code == 0

        # Suite passed to start_scan, not set_scope
        call_kwargs = client.start_scan.call_args
        assert call_kwargs[1].get("suites") == ["network"] or (
            call_kwargs[0] and "network" in (call_kwargs[1].get("suites") or [])
        )

    def test_scan_with_checks(self, runner):
        """scan --checks passes check names to start_scan."""
        client = _mock_client()
        client.set_scope.return_value = {"status": "ok", "target": "example.com"}
        client.update_settings.return_value = {"status": "ok"}
        client.start_scan.return_value = {"status": "accepted"}
        client.poll_scan.return_value = {"status": "complete"}
        client.get_observations.return_value = {"total": 0, "observations": []}

        with _patch_client(client):
            result = runner.invoke(
                cli,
                [
                    "scan",
                    "example.com",
                    "-c",
                    "dns_enumeration",
                    "-c",
                    "header_analysis",
                    "--quiet",
                ],
            )
            assert result.exit_code == 0

        call_kwargs = client.start_scan.call_args[1]
        assert sorted(call_kwargs.get("checks")) == ["dns_enumeration", "header_analysis"]
        assert call_kwargs.get("suites") is None

    def test_scan_with_scenario(self, runner):
        """scan --scenario loads scenario via API."""
        client = _mock_client()
        client.set_scope.return_value = {"status": "ok"}
        client.update_settings.return_value = {"status": "ok"}
        client.load_scenario.return_value = {"loaded": True, "simulation_count": 5, "scenario": {}}
        client.start_scan.return_value = {"status": "accepted"}
        client.poll_scan.return_value = {"status": "complete"}
        client.get_observations.return_value = {"total": 0, "observations": []}

        with _patch_client(client):
            result = runner.invoke(
                cli, ["scan", "example.com", "--scenario", "fakobanko", "--quiet"]
            )
            assert result.exit_code == 0

        client.load_scenario.assert_called_once_with("fakobanko")

    def test_scan_plan(self, runner):
        """scan --plan shows execution plan."""
        client = _mock_client()
        client.set_scope.return_value = {"status": "ok"}
        client.update_settings.return_value = {"status": "ok"}
        client.get_scan_checks.return_value = {
            "checks": [
                {
                    "name": "dns_enumeration",
                    "suite": "network",
                    "conditions": [],
                    "produces": ["subdomains"],
                },
                {"name": "header_analysis", "suite": "web", "conditions": [], "produces": []},
            ],
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["scan", "example.com", "--plan"])
            assert result.exit_code == 0
            assert "Execution Plan" in result.output

    def test_scan_dry_run(self, runner):
        """scan --dry-run validates without running."""
        client = _mock_client()
        client.set_scope.return_value = {"status": "ok"}
        client.update_settings.return_value = {"status": "ok"}
        client.get_scan_checks.return_value = {
            "checks": [
                {"name": "dns_enumeration", "suite": "network"},
            ],
        }

        with _patch_client(client):
            result = runner.invoke(cli, ["scan", "example.com", "--dry-run"])
            assert result.exit_code == 0
            assert "Configuration valid" in result.output


class TestExportCommand:
    """Tests for export command."""

    def test_export_json_to_md(self, runner, sample_observations):
        """export converts JSON to Markdown."""
        input_json = json.dumps(sample_observations)

        result = runner.invoke(cli, ["export", "-f", "md"], input=input_json)
        assert result.exit_code == 0
        assert "# Chainsmith Recon Report" in result.output

    def test_export_json_to_sarif(self, runner, sample_observations):
        """export converts JSON to SARIF."""
        input_json = json.dumps(sample_observations)

        result = runner.invoke(cli, ["export", "-f", "sarif"], input=input_json)
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert data["version"] == "2.1.0"


class TestServeCommand:
    """Tests for serve command."""

    def test_serve_help(self, runner):
        """serve --help shows options."""
        result = runner.invoke(cli, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output
        assert "--port" in result.output
        assert "--reload" in result.output
