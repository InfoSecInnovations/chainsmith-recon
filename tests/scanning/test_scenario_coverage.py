"""
Coverage matrix test — asserts every registered check has at least one
scenario that lists a corresponding expected finding.
"""

import json
from pathlib import Path

import pytest

from app.check_resolver import get_real_checks
from app.engine.chains import CHAIN_PATTERNS

pytestmark = pytest.mark.unit

SCENARIOS_DIR = Path(__file__).resolve().parents[2] / "scenarios"


def _load_scenario(name: str) -> dict:
    """Load a scenario.json by name."""
    path = SCENARIOS_DIR / name / "scenario.json"
    return json.loads(path.read_text())


def _all_scenario_names() -> list[str]:
    """Discover all scenario directories containing scenario.json."""
    return [
        d.name for d in SCENARIOS_DIR.iterdir() if d.is_dir() and (d / "scenario.json").exists()
    ]


@pytest.fixture(scope="module")
def all_checks():
    """Get all registered check instances."""
    return get_real_checks()


@pytest.fixture(scope="module")
def all_scenarios():
    """Load all scenario configs."""
    return {name: _load_scenario(name) for name in _all_scenario_names()}


@pytest.fixture(scope="module")
def merged_expected_findings(all_scenarios):
    """Union of expected_findings across all scenarios."""
    merged = set()
    for scenario in all_scenarios.values():
        for f in scenario.get("expected_findings", []):
            # Extract check name from finding ID (prefix before first dash-host)
            merged.add(f)
    return merged


@pytest.fixture(scope="module")
def merged_expected_chains(all_scenarios):
    """Union of expected_chains across all scenarios."""
    merged = set()
    for scenario in all_scenarios.values():
        merged.update(scenario.get("expected_chains", []))
    return merged


class TestCheckCoverage:
    """Every registered check should be exercised by at least one scenario."""

    def test_all_checks_have_scenario_coverage(self, all_checks, merged_expected_findings):
        """For every check, at least one scenario lists a finding whose ID
        starts with the check's name."""
        uncovered = []
        for check in all_checks:
            check_name = check.name
            # A finding is considered "covering" if its ID starts with the check name
            has_coverage = any(
                f.startswith(check_name) or f.startswith(check_name.replace("_", "-"))
                for f in merged_expected_findings
            )
            if not has_coverage:
                uncovered.append(check_name)

        assert not uncovered, (
            f"{len(uncovered)} checks have no corresponding expected_finding "
            f"in any scenario:\n  " + "\n  ".join(sorted(uncovered))
        )

    def test_fakobanko_covers_all_suites(self, all_scenarios):
        """fakobanko scenario has expected findings from all 7 suites."""
        scenario = all_scenarios.get("fakobanko")
        if scenario is None:
            pytest.skip("fakobanko scenario not found")

        findings = scenario.get("expected_findings", [])
        # Check for at least one finding from each suite by prefix
        suite_prefixes = {
            "network": [
                "dns_",
                "tls_",
                "port_",
                "service_probe",
                "banner_",
                "whois_",
                "geoip",
                "reverse_dns",
                "ipv6_",
                "http_method",
                "traceroute",
            ],
            "web": [
                "header_",
                "cookie_",
                "cors_",
                "robots_",
                "waf_",
                "auth_detection",
                "favicon",
                "http2_",
                "path_probe",
                "sitemap",
                "error_page",
                "openapi_",
                "webdav",
                "vcs_",
                "config_exposure",
                "directory_",
                "default_creds",
                "debug_endpoints",
                "redirect_",
                "ssrf_",
                "mass_assignment",
                "hsts_",
                "sri_",
            ],
            "ai": [
                "llm_endpoint",
                "embedding_",
                "model_info",
                "ai_framework",
                "ai_error",
                "content_filter",
                "rate_limit",
                "context_window",
                "model_enumeration",
                "api_parameter",
                "system_prompt",
                "tool_discovery",
                "prompt_leakage",
                "output_format",
                "jailbreak",
                "multiturn",
                "input_format",
                "token_cost",
                "cache_detect",
                "auth_bypass",
                "adversarial",
                "function_abuse",
                "guardrail",
                "history_leak",
                "streaming",
                "training_data",
                "model_fingerprint",
            ],
            "mcp": ["mcp_"],
            "agent": ["agent_"],
            "rag": ["rag_"],
            "cag": ["cag_"],
        }

        missing_suites = []
        for suite, prefixes in suite_prefixes.items():
            has_suite = any(any(f.startswith(prefix) for prefix in prefixes) for f in findings)
            if not has_suite:
                missing_suites.append(suite)

        assert not missing_suites, (
            f"fakobanko is missing expected findings from suites: {missing_suites}"
        )

    def test_demo_domain_covers_all_suites(self, all_scenarios):
        """demo-domain scenario has expected findings from all 7 suites."""
        scenario = all_scenarios.get("demo-domain")
        if scenario is None:
            pytest.skip("demo-domain scenario not found")

        findings = scenario.get("expected_findings", [])
        suite_indicators = {
            "network": ["dns_", "service_probe", "tls_", "http_method"],
            "web": [
                "header_",
                "robots_",
                "cors_",
                "openapi_",
                "cookie_",
                "config_exposure",
                "debug_endpoints",
                "directory_",
                "auth_detection",
            ],
            "ai": [
                "llm_endpoint",
                "ai_framework",
                "model_info",
                "prompt_leakage",
                "rate_limit",
                "tool_discovery",
                "ai_error",
                "jailbreak",
                "multiturn",
                "guardrail",
                "history_leak",
            ],
            "mcp": ["mcp_"],
            "agent": ["agent_"],
            "rag": ["rag_"],
            "cag": ["cag_"],
        }

        missing_suites = []
        for suite, prefixes in suite_indicators.items():
            has_suite = any(any(f.startswith(prefix) for prefix in prefixes) for f in findings)
            if not has_suite:
                missing_suites.append(suite)

        assert not missing_suites, (
            f"demo-domain is missing expected findings from suites: {missing_suites}"
        )


class TestChainCoverage:
    """Every chain pattern should be triggerable by at least one scenario."""

    def test_all_chain_patterns_covered(self, merged_expected_chains):
        """Every defined chain pattern appears in at least one scenario's
        expected_chains list."""
        pattern_names = {p["name"] for p in CHAIN_PATTERNS}
        uncovered = pattern_names - merged_expected_chains

        assert not uncovered, (
            f"{len(uncovered)} chain patterns have no scenario coverage:\n  "
            + "\n  ".join(sorted(uncovered))
        )

    def test_fakobanko_chain_coverage(self, all_scenarios):
        """fakobanko triggers >= 30 of 42 chain patterns."""
        scenario = all_scenarios.get("fakobanko")
        if scenario is None:
            pytest.skip("fakobanko scenario not found")

        chains = scenario.get("expected_chains", [])
        assert len(chains) >= 30, f"fakobanko has {len(chains)} expected chains, need >= 30"

    def test_demo_domain_chain_coverage(self, all_scenarios):
        """demo-domain triggers >= 15 chain patterns."""
        scenario = all_scenarios.get("demo-domain")
        if scenario is None:
            pytest.skip("demo-domain scenario not found")

        chains = scenario.get("expected_chains", [])
        assert len(chains) >= 15, f"demo-domain has {len(chains)} expected chains, need >= 15"
