"""
Tests for app/advisors/scan_planner_advisor.py

Covers:
- ScanPlannerRecommendation dataclass
- No exclusions rule
- Third-party CDN detection
- Proof-of-scope readiness
- AI suite suggestion
- Engagement window check
- Single domain broad ports
- No recommendations when scope is clean
"""

import pytest

from app.advisors.scan_planner_advisor import ScanPlannerAdvisor, ScanPlannerRecommendation
from app.models import ScopeDefinition

pytestmark = pytest.mark.unit


# ── Helpers ──────────────────────────────────────────────────────


def _make_advisor(
    in_scope=None,
    out_of_scope=None,
    time_window=None,
    available_checks=None,
    check_metadata=None,
    proof_config=None,
    in_scope_ports=None,
) -> ScanPlannerAdvisor:
    """Build a ScanPlannerAdvisor with sensible defaults for testing."""
    scope = ScopeDefinition(
        in_scope_domains=in_scope or [],
        out_of_scope_domains=out_of_scope or [],
        time_window=time_window,
        in_scope_ports=in_scope_ports or [],
    )
    return ScanPlannerAdvisor(
        scope=scope,
        available_checks=available_checks or set(),
        check_metadata=check_metadata or {},
        proof_of_scope_config=proof_config or {},
    )


# ═══════════════════════════════════════════════════════════════════
# Recommendation Dataclass
# ═══════════════════════════════════════════════════════════════════


class TestScanPlannerRecommendation:
    def test_defaults(self):
        rec = ScanPlannerRecommendation(
            category="readiness", reason="test", suggestion="do something"
        )
        assert rec.confidence == "medium"
        assert rec.auto_fixable is False
        assert rec.fix_action == {}

    def test_to_dict(self):
        rec = ScanPlannerRecommendation(
            category="scope_completeness",
            reason="test reason",
            suggestion="test suggestion",
            confidence="high",
            auto_fixable=True,
            fix_action={"add_exclusion": "cdn.example.com"},
        )
        d = rec.to_dict()
        assert d["category"] == "scope_completeness"
        assert d["suggestion"] == "test suggestion"
        assert d["auto_fixable"] is True
        assert d["fix_action"]["add_exclusion"] == "cdn.example.com"

    def test_to_dict_no_fix_action(self):
        rec = ScanPlannerRecommendation(
            category="readiness", reason="test", suggestion="do something"
        )
        d = rec.to_dict()
        assert d["fix_action"] is None


# ═══════════════════════════════════════════════════════════════════
# No Exclusions Rule
# ═══════════════════════════════════════════════════════════════════


class TestNoExclusions:
    def test_flags_when_no_exclusions(self):
        advisor = _make_advisor(in_scope=["example.com"])
        recs = advisor.analyze()
        no_excl_recs = [
            r
            for r in recs
            if r.category == "scope_completeness" and "no exclusions" in r.reason.lower()
        ]
        assert len(no_excl_recs) == 1
        assert "out-of-scope" in no_excl_recs[0].suggestion.lower()

    def test_no_flag_when_exclusions_exist(self):
        advisor = _make_advisor(in_scope=["example.com"], out_of_scope=["cdn.example.com"])
        recs = advisor.analyze()
        no_excl_recs = [
            r
            for r in recs
            if r.category == "scope_completeness" and "no exclusions" in r.reason.lower()
        ]
        assert len(no_excl_recs) == 0

    def test_no_flag_when_no_scope(self):
        advisor = _make_advisor()
        recs = advisor.analyze()
        scope_recs = [
            r
            for r in recs
            if r.category == "scope_completeness" and "no exclusions" in r.reason.lower()
        ]
        assert len(scope_recs) == 0


# ═══════════════════════════════════════════════════════════════════
# Third-Party CDN Detection
# ═══════════════════════════════════════════════════════════════════


class TestThirdPartyDetection:
    def test_flags_cdn_in_scope(self):
        advisor = _make_advisor(in_scope=["cdn.example.cloudfront.net"])
        recs = advisor.analyze()
        cdn_recs = [r for r in recs if r.auto_fixable and "third-party" in r.reason.lower()]
        assert len(cdn_recs) >= 1

    def test_no_flag_when_cdn_already_excluded(self):
        advisor = _make_advisor(
            in_scope=["cdn.example.cloudfront.net"],
            out_of_scope=["cdn.example.cloudfront.net"],
        )
        recs = advisor.analyze()
        cdn_recs = [r for r in recs if r.auto_fixable and "cloudfront" in r.reason.lower()]
        assert len(cdn_recs) == 0

    def test_no_flag_for_normal_domain(self):
        advisor = _make_advisor(in_scope=["app.example.com"])
        recs = advisor.analyze()
        cdn_recs = [r for r in recs if r.auto_fixable and "third-party" in r.reason.lower()]
        assert len(cdn_recs) == 0


# ═══════════════════════════════════════════════════════════════════
# Proof-of-Scope Readiness
# ═══════════════════════════════════════════════════════════════════


class TestProofOfScope:
    def test_flags_when_not_configured(self):
        advisor = _make_advisor(in_scope=["example.com"])
        recs = advisor.analyze()
        pos_recs = [r for r in recs if r.category == "readiness" and "proof" in r.reason.lower()]
        assert len(pos_recs) == 1

    def test_no_flag_when_configured(self):
        advisor = _make_advisor(in_scope=["example.com"], proof_config={"enabled": True})
        recs = advisor.analyze()
        pos_recs = [r for r in recs if r.category == "readiness" and "proof" in r.reason.lower()]
        assert len(pos_recs) == 0


# ═══════════════════════════════════════════════════════════════════
# AI Suite Suggestion
# ═══════════════════════════════════════════════════════════════════


class TestAISuiteSuggestion:
    def test_suggests_ai_suite_for_api_target(self):
        advisor = _make_advisor(
            in_scope=["api.example.com"],
            available_checks={"llm_endpoint_discovery", "prompt_leakage", "dns_enumeration"},
            check_metadata={
                "llm_endpoint_discovery": {"suite": "ai"},
                "prompt_leakage": {"suite": "ai"},
                "dns_enumeration": {"suite": "network"},
            },
        )
        recs = advisor.analyze()
        ai_recs = [r for r in recs if r.category == "check_selection"]
        assert len(ai_recs) >= 1

    def test_no_suggestion_for_non_api_target(self):
        advisor = _make_advisor(
            in_scope=["www.example.com"],
            available_checks={"llm_endpoint_discovery"},
            check_metadata={"llm_endpoint_discovery": {"suite": "ai"}},
        )
        recs = advisor.analyze()
        ai_recs = [r for r in recs if r.category == "check_selection"]
        assert len(ai_recs) == 0


# ═══════════════════════════════════════════════════════════════════
# Engagement Window
# ═══════════════════════════════════════════════════════════════════


class TestEngagementWindow:
    def test_flags_when_no_window(self):
        advisor = _make_advisor(in_scope=["example.com"])
        recs = advisor.analyze()
        window_recs = [
            r for r in recs if r.category == "readiness" and "window" in r.reason.lower()
        ]
        assert len(window_recs) == 1

    def test_no_flag_when_window_set(self):
        advisor = _make_advisor(in_scope=["example.com"], time_window="2026-04-01 to 2026-04-30")
        recs = advisor.analyze()
        window_recs = [
            r for r in recs if r.category == "readiness" and "window" in r.reason.lower()
        ]
        assert len(window_recs) == 0


# ═══════════════════════════════════════════════════════════════════
# Single Domain Broad Ports
# ═══════════════════════════════════════════════════════════════════


class TestSingleDomainBroadPorts:
    def test_flags_broad_port_range(self):
        advisor = _make_advisor(
            in_scope=["example.com"],
            in_scope_ports=list(range(1, 65536)),
        )
        recs = advisor.analyze()
        port_recs = [r for r in recs if r.category == "target_analysis"]
        assert len(port_recs) == 1

    def test_no_flag_for_multiple_domains(self):
        advisor = _make_advisor(
            in_scope=["example.com", "api.example.com"],
            in_scope_ports=list(range(1, 65536)),
        )
        recs = advisor.analyze()
        port_recs = [r for r in recs if r.category == "target_analysis"]
        assert len(port_recs) == 0

    def test_no_flag_for_small_port_range(self):
        advisor = _make_advisor(
            in_scope=["example.com"],
            in_scope_ports=[80, 443, 8080],
        )
        recs = advisor.analyze()
        port_recs = [r for r in recs if r.category == "target_analysis"]
        assert len(port_recs) == 0


# ═══════════════════════════════════════════════════════════════════
# Clean Scope (No Recommendations)
# ═══════════════════════════════════════════════════════════════════


class TestCleanScope:
    def test_minimal_recommendations_when_scope_clean(self):
        """A well-configured scope should produce minimal recommendations."""
        advisor = _make_advisor(
            in_scope=["app.example.com"],
            out_of_scope=["cdn.example.com"],
            time_window="2026-04-01 to 2026-04-30",
            proof_config={"enabled": True},
        )
        recs = advisor.analyze()
        # Should have no scope_completeness, readiness, or target_analysis issues
        # (may still have check_selection depending on check metadata)
        serious_recs = [r for r in recs if r.category in ("scope_completeness", "readiness")]
        assert len(serious_recs) == 0
