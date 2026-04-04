"""
tests/test_on_critical.py - Tests for on_critical infrastructure (Phase 6a-0)

Tests:
- Preference resolution (global, per-suite override, fallback)
- CheckLauncher skip behavior (skip_downstream)
- CheckLauncher annotate behavior
- CheckLauncher stop behavior
- Intrusive check gating
"""

from dataclasses import dataclass, field
from unittest.mock import patch

import pytest

from app.check_launcher import CheckLauncher
from app.checks.base import CheckCondition, CheckResult, Finding, Service
from app.preferences import (
    VALID_ON_CRITICAL_VALUES,
    CheckPreferences,
    Preferences,
    resolve_on_critical,
)

# ─── Fixtures ────────────────────────────────────────────────────────────


@dataclass
class FakeCheck:
    """Minimal check object for testing launcher behavior."""

    name: str
    conditions: list = field(default_factory=list)
    produces: list = field(default_factory=list)
    _findings: list = field(default_factory=list)
    _outputs: dict = field(default_factory=dict)

    async def run(self, context: dict) -> CheckResult:
        result = CheckResult(success=True)
        result.findings = list(self._findings)
        result.outputs = dict(self._outputs)
        return result


def make_finding(
    title: str = "Test finding",
    severity: str = "info",
    host: str = "example.com",
    check_name: str = "test_check",
) -> Finding:
    return Finding(
        id=f"{check_name}-{host}-{title}",
        title=title,
        severity=severity,
        description="Test description",
        evidence="Test evidence",
        target=Service(url=f"http://{host}:80", host=host, port=80),
        check_name=check_name,
    )


def make_critical_finding(
    host: str = "example.com",
    check_name: str = "test_check",
    title: str = "Critical vuln",
) -> Finding:
    return make_finding(title=title, severity="critical", host=host, check_name=check_name)


# ─── Preference Resolution ──────────────────────────────────────────────


class TestResolveOnCritical:
    def test_global_default(self):
        prefs = Preferences()
        assert resolve_on_critical(prefs, "web") == "annotate"

    def test_global_set_to_stop(self):
        prefs = Preferences()
        prefs.checks.on_critical = "stop"
        assert resolve_on_critical(prefs, "web") == "stop"
        assert resolve_on_critical(prefs, "ai") == "stop"

    def test_per_suite_override(self):
        prefs = Preferences()
        prefs.checks.on_critical = "annotate"
        prefs.checks.on_critical_web = "skip_downstream"
        assert resolve_on_critical(prefs, "web") == "skip_downstream"
        assert resolve_on_critical(prefs, "ai") == "annotate"  # fallback to global

    def test_per_suite_none_falls_back(self):
        prefs = Preferences()
        prefs.checks.on_critical = "stop"
        prefs.checks.on_critical_web = None  # Not set
        assert resolve_on_critical(prefs, "web") == "stop"

    def test_invalid_suite_value_falls_back(self):
        prefs = Preferences()
        prefs.checks.on_critical = "annotate"
        prefs.checks.on_critical_web = "invalid_value"
        assert resolve_on_critical(prefs, "web") == "annotate"

    def test_unknown_suite_falls_back(self):
        prefs = Preferences()
        prefs.checks.on_critical = "stop"
        assert resolve_on_critical(prefs, "nonexistent") == "stop"

    def test_all_valid_values(self):
        for val in VALID_ON_CRITICAL_VALUES:
            prefs = Preferences()
            prefs.checks.on_critical = val
            assert resolve_on_critical(prefs, "web") == val


class TestCheckPreferencesFields:
    def test_defaults(self):
        cp = CheckPreferences()
        assert cp.on_critical == "annotate"
        assert cp.on_critical_web is None
        assert cp.on_critical_ai is None
        assert cp.on_critical_network is None
        assert cp.intrusive_web is False

    def test_intrusive_web_off_by_default(self):
        prefs = Preferences()
        assert prefs.checks.intrusive_web is False

    def test_aggressive_profile_enables_intrusive(self):
        from app.preferences import BUILTIN_PROFILES

        aggressive = BUILTIN_PROFILES["aggressive"]
        resolved = aggressive.resolve()
        assert resolved.checks.intrusive_web is True


# ─── CheckLauncher: on_critical behavior ─────────────────────────────────


class TestLauncherAnnotate:
    """Test that findings are annotated when on_critical='annotate'."""

    @pytest.mark.asyncio
    async def test_annotates_downstream_findings(self):
        """When web check produces critical finding, AI findings get annotated."""
        web_check = FakeCheck(
            name="header_analysis",
            produces=["header_findings"],
            _findings=[make_critical_finding(host="target.com", check_name="header_analysis")],
            _outputs={"header_findings": True},
        )
        ai_check = FakeCheck(
            name="llm_endpoint",
            conditions=[CheckCondition("header_findings", "truthy")],
            _findings=[
                make_finding(
                    title="Prompt leak",
                    severity="medium",
                    host="target.com",
                    check_name="llm_endpoint",
                )
            ],
        )

        context = {}
        launcher = CheckLauncher([web_check, ai_check], context)

        with patch.object(launcher, "_resolve_on_critical", return_value="annotate"):
            findings = await launcher.run_all()

        assert len(findings) == 2
        # The AI finding should be annotated
        ai_finding = next(f for f in findings if f.get("check_name") == "llm_endpoint")
        assert ai_finding.get("raw_data", {}).get("critical_finding_on_host") is True
        assert ai_finding["raw_data"]["critical_finding_source"]["suite"] == "web"

    @pytest.mark.asyncio
    async def test_same_suite_not_annotated(self):
        """Findings from the same suite as the critical are NOT annotated."""
        check1 = FakeCheck(
            name="header_analysis",
            produces=["header_findings"],
            _findings=[make_critical_finding(host="target.com", check_name="header_analysis")],
            _outputs={"header_findings": True},
        )
        check2 = FakeCheck(
            name="robots_txt",
            conditions=[CheckCondition("header_findings", "truthy")],
            _findings=[
                make_finding(
                    title="Sensitive paths",
                    severity="low",
                    host="target.com",
                    check_name="robots_txt",
                )
            ],
        )

        context = {}
        launcher = CheckLauncher([check1, check2], context)

        with patch.object(launcher, "_resolve_on_critical", return_value="annotate"):
            findings = await launcher.run_all()

        # robots_txt is also "web" suite — should NOT be annotated
        robots_finding = next(f for f in findings if f.get("check_name") == "robots_txt")
        raw = robots_finding.get("raw_data") or {}
        assert raw.get("critical_finding_on_host") is not True


class TestLauncherSkipDownstream:
    """Test that downstream checks are skipped when on_critical='skip_downstream'."""

    @pytest.mark.asyncio
    async def test_skips_downstream_suite(self):
        """AI checks are skipped when web has critical + skip_downstream."""
        web_check = FakeCheck(
            name="header_analysis",
            produces=["header_findings"],
            _findings=[make_critical_finding(host="target.com", check_name="header_analysis")],
            _outputs={"header_findings": True},
        )
        ai_check = FakeCheck(
            name="llm_endpoint",
            conditions=[CheckCondition("header_findings", "truthy")],
            _findings=[
                make_finding(
                    title="Should not appear",
                    severity="high",
                    host="target.com",
                    check_name="llm_endpoint",
                )
            ],
        )

        context = {}
        launcher = CheckLauncher([web_check, ai_check], context)

        with patch.object(launcher, "_resolve_on_critical", return_value="skip_downstream"):
            findings = await launcher.run_all()

        # Only the web finding should be present
        assert len(findings) == 1
        assert findings[0]["check_name"] == "header_analysis"
        assert "llm_endpoint" in launcher.skipped

    @pytest.mark.asyncio
    async def test_same_suite_not_skipped(self):
        """Checks in the same suite are NOT skipped."""
        check1 = FakeCheck(
            name="header_analysis",
            produces=["header_findings"],
            _findings=[make_critical_finding(host="target.com", check_name="header_analysis")],
            _outputs={"header_findings": True},
        )
        check2 = FakeCheck(
            name="path_probe",
            conditions=[CheckCondition("header_findings", "truthy")],
            _findings=[
                make_finding(
                    title="Path found",
                    severity="info",
                    host="target.com",
                    check_name="path_probe",
                )
            ],
        )

        context = {}
        launcher = CheckLauncher([check1, check2], context)

        with patch.object(launcher, "_resolve_on_critical", return_value="skip_downstream"):
            findings = await launcher.run_all()

        # Both are web suite — path_probe should NOT be skipped
        assert len(findings) == 2
        assert "path_probe" not in launcher.skipped


class TestLauncherStop:
    """Test that scan stops when on_critical='stop'."""

    @pytest.mark.asyncio
    async def test_stops_scan(self):
        """Scan halts immediately when critical finding + on_critical='stop'."""
        web_check = FakeCheck(
            name="header_analysis",
            produces=["header_findings"],
            _findings=[make_critical_finding(host="target.com", check_name="header_analysis")],
            _outputs={"header_findings": True},
        )
        ai_check = FakeCheck(
            name="llm_endpoint",
            conditions=[CheckCondition("header_findings", "truthy")],
            _findings=[
                make_finding(
                    title="Should not run",
                    severity="medium",
                    host="target.com",
                    check_name="llm_endpoint",
                )
            ],
        )

        context = {}
        launcher = CheckLauncher([web_check, ai_check], context)

        with patch.object(launcher, "_resolve_on_critical", return_value="stop"):
            findings = await launcher.run_all()

        assert launcher.scan_stopped is True
        # Only the critical finding from the first check
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"


class TestLauncherNoCriticals:
    """Test normal behavior when no critical findings exist."""

    @pytest.mark.asyncio
    async def test_no_skip_without_criticals(self):
        """Non-critical findings don't trigger any on_critical behavior."""
        check1 = FakeCheck(
            name="header_analysis",
            produces=["header_findings"],
            _findings=[
                make_finding(
                    title="Low finding",
                    severity="low",
                    host="target.com",
                    check_name="header_analysis",
                )
            ],
            _outputs={"header_findings": True},
        )
        check2 = FakeCheck(
            name="llm_endpoint",
            conditions=[CheckCondition("header_findings", "truthy")],
            _findings=[
                make_finding(
                    title="AI finding",
                    severity="medium",
                    host="target.com",
                    check_name="llm_endpoint",
                )
            ],
        )

        context = {}
        launcher = CheckLauncher([check1, check2], context)

        with patch.object(launcher, "_resolve_on_critical", return_value="skip_downstream"):
            findings = await launcher.run_all()

        assert len(findings) == 2
        assert len(launcher.skipped) == 0


class TestLauncherCriticalHosts:
    """Test that critical_hosts is properly tracked in context."""

    @pytest.mark.asyncio
    async def test_critical_hosts_in_context(self):
        web_check = FakeCheck(
            name="header_analysis",
            _findings=[
                make_critical_finding(host="host1.com", check_name="header_analysis"),
                make_critical_finding(host="host2.com", check_name="header_analysis"),
            ],
        )

        context = {}
        launcher = CheckLauncher([web_check], context)

        with patch.object(launcher, "_resolve_on_critical", return_value="annotate"):
            await launcher.run_all()

        assert "host1.com" in context["critical_hosts"]
        assert "host2.com" in context["critical_hosts"]
        assert context["critical_hosts"]["host1.com"][0]["suite"] == "web"


# ─── Intrusive Gating ───────────────────────────────────────────────────


class TestIntrusiveGating:
    """Test that intrusive_web preference gates checks correctly."""

    def test_intrusive_web_default_false(self):
        prefs = Preferences()
        assert prefs.checks.intrusive_web is False

    def test_intrusive_web_serializes(self):
        prefs = Preferences()
        prefs.checks.intrusive_web = True
        d = prefs.to_dict()
        assert d["checks"]["intrusive_web"] is True

        restored = Preferences.from_dict(d)
        assert restored.checks.intrusive_web is True

    def test_intrusive_web_in_aggressive_profile(self):
        from app.preferences import BUILTIN_PROFILES

        aggressive = BUILTIN_PROFILES["aggressive"]
        resolved = aggressive.resolve()
        assert resolved.checks.intrusive_web is True

    def test_intrusive_web_not_in_stealth_profile(self):
        from app.preferences import BUILTIN_PROFILES

        stealth = BUILTIN_PROFILES["stealth"]
        resolved = stealth.resolve()
        assert resolved.checks.intrusive_web is False
