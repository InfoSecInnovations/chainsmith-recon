"""
Tests for app/advisors/scan_analysis_advisor.py

Covers:
- ScanAnalysisRecommendation dataclass
- ScanAnalysisAdvisorConfig defaults (disabled by default)
- Gap analysis: detects checks blocked by missing context
- Partial results: flags failed and skipped checks
- Follow-up suggestions: triggers based on observations
- Coverage cross-reference: detects suites with low/no coverage
- Deduplication of recommendations
- Disabled advisor returns empty list
"""

import pytest

from app.advisors.scan_analysis_advisor import (
    ScanAnalysisAdvisor,
    ScanAnalysisAdvisorConfig,
    ScanAnalysisRecommendation,
)

pytestmark = pytest.mark.unit

# ── Helpers ──────────────────────────────────────────────────────


def _make_advisor(
    completed=None,
    failed=None,
    skipped=None,
    all_check_names=None,
    context=None,
    observations=None,
    check_metadata=None,
    enabled=True,
) -> ScanAnalysisAdvisor:
    """Build a ScanAnalysisAdvisor with sensible defaults for testing."""
    return ScanAnalysisAdvisor(
        completed=completed or set(),
        failed=failed or set(),
        skipped=skipped or set(),
        all_check_names=all_check_names or set(),
        context=context or {},
        observations=observations or [],
        check_metadata=check_metadata or {},
        config=ScanAnalysisAdvisorConfig(enabled=enabled),
    )


# ═══════════════════════════════════════════════════════════════════
# Recommendation Dataclass
# ═══════════════════════════════════════════════════════════════════


class TestScanAnalysisRecommendation:
    def test_defaults(self):
        rec = ScanAnalysisRecommendation(check_name="foo", reason="bar")
        assert rec.confidence == "medium"
        assert rec.category == "gap_analysis"
        assert rec.context_injection == {}

    def test_to_dict(self):
        rec = ScanAnalysisRecommendation(
            check_name="test_check",
            reason="test reason",
            confidence="high",
            category="config_suggestion",
        )
        d = rec.to_dict()
        assert d["check_name"] == "test_check"
        assert d["reason"] == "test reason"
        assert d["confidence"] == "high"
        assert d["category"] == "config_suggestion"


# ═══════════════════════════════════════════════════════════════════
# Disabled Advisor
# ═══════════════════════════════════════════════════════════════════


class TestDisabledAdvisor:
    def test_returns_empty_when_disabled(self):
        advisor = _make_advisor(enabled=False)
        assert advisor.analyze() == []


# ═══════════════════════════════════════════════════════════════════
# Gap Analysis
# ═══════════════════════════════════════════════════════════════════


class TestGapAnalysis:
    def test_detects_checks_blocked_by_missing_context(self):
        """Checks that never ran due to unmet conditions are flagged."""
        advisor = _make_advisor(
            completed={"dns_enumeration"},
            all_check_names={"dns_enumeration", "port_scan"},
            context={"scope_domains": ["example.com"]},
            check_metadata={
                "port_scan": {
                    "conditions": ["target_hosts truthy"],
                    "produces": ["services"],
                },
            },
        )
        recs = advisor.analyze()
        gap_recs = [r for r in recs if r.category == "gap_analysis" and r.check_name == "port_scan"]
        assert len(gap_recs) == 1
        assert "target_hosts" in gap_recs[0].reason

    def test_no_gap_when_check_ran(self):
        """Checks that completed should not appear in gap analysis."""
        advisor = _make_advisor(
            completed={"dns_enumeration", "port_scan"},
            all_check_names={"dns_enumeration", "port_scan"},
            context={"target_hosts": ["1.2.3.4"], "services": []},
            check_metadata={
                "port_scan": {
                    "conditions": ["target_hosts truthy"],
                    "produces": ["services"],
                },
            },
        )
        recs = advisor.analyze()
        gap_recs = [r for r in recs if r.check_name == "port_scan" and r.category == "gap_analysis"]
        assert len(gap_recs) == 0

    def test_no_gap_when_context_satisfied(self):
        """Checks with satisfied conditions but that never ran for other reasons
        should still show up (they were in never_ran)."""
        advisor = _make_advisor(
            completed=set(),
            all_check_names={"port_scan"},
            context={"target_hosts": ["1.2.3.4"]},
            check_metadata={
                "port_scan": {
                    "conditions": ["target_hosts truthy"],
                    "produces": ["services"],
                },
            },
        )
        recs = advisor.analyze()
        # port_scan never ran but context IS satisfied — no missing keys
        gap_recs = [r for r in recs if r.check_name == "port_scan" and r.category == "gap_analysis"]
        assert len(gap_recs) == 0


# ═══════════════════════════════════════════════════════════════════
# Partial Results
# ═══════════════════════════════════════════════════════════════════


class TestPartialResults:
    def test_flags_failed_checks(self):
        advisor = _make_advisor(
            failed={"service_probe"},
            all_check_names={"service_probe"},
            check_metadata={"service_probe": {"conditions": [], "produces": []}},
        )
        recs = advisor.analyze()
        failed_recs = [r for r in recs if r.check_name == "service_probe"]
        assert len(failed_recs) == 1
        assert "failed" in failed_recs[0].reason.lower()

    def test_flags_skipped_checks(self):
        advisor = _make_advisor(
            skipped={"header_analysis"},
            all_check_names={"header_analysis"},
            check_metadata={"header_analysis": {"conditions": [], "produces": []}},
        )
        recs = advisor.analyze()
        skipped_recs = [r for r in recs if r.check_name == "header_analysis"]
        assert len(skipped_recs) == 1
        assert "skipped" in skipped_recs[0].reason.lower()


# ═══════════════════════════════════════════════════════════════════
# Follow-Up Suggestions
# ═══════════════════════════════════════════════════════════════════


class TestFollowUpSuggestions:
    def test_suggests_followup_when_trigger_has_observations(self):
        """When llm_endpoint_discovery has observations and prompt_leakage didn't run."""
        advisor = _make_advisor(
            completed={"llm_endpoint_discovery"},
            all_check_names={"llm_endpoint_discovery", "prompt_leakage"},
            observations=[{"check_name": "llm_endpoint_discovery", "title": "Found LLM"}],
            check_metadata={
                "prompt_leakage": {"conditions": ["chat_endpoints truthy"], "produces": []},
            },
        )
        recs = advisor.analyze()
        followup_recs = [r for r in recs if r.check_name == "prompt_leakage"]
        assert len(followup_recs) >= 1

    def test_no_followup_when_already_ran(self):
        """Don't suggest a check that already ran."""
        advisor = _make_advisor(
            completed={"llm_endpoint_discovery", "prompt_leakage"},
            all_check_names={"llm_endpoint_discovery", "prompt_leakage"},
            observations=[{"check_name": "llm_endpoint_discovery", "title": "Found LLM"}],
            check_metadata={},
        )
        recs = advisor.analyze()
        followup_recs = [r for r in recs if r.check_name == "prompt_leakage"]
        assert len(followup_recs) == 0

    def test_no_followup_when_trigger_has_no_observations(self):
        """Don't suggest follow-ups for checks that produced no observations."""
        advisor = _make_advisor(
            completed={"llm_endpoint_discovery"},
            all_check_names={"llm_endpoint_discovery", "prompt_leakage"},
            observations=[],  # no observations
            check_metadata={
                "prompt_leakage": {"conditions": ["chat_endpoints truthy"], "produces": []},
            },
        )
        recs = advisor.analyze()
        followup_recs = [r for r in recs if r.check_name == "prompt_leakage"]
        # May still appear from gap_analysis but NOT from follow-up
        for r in followup_recs:
            assert r.category != "follow_up"


# ═══════════════════════════════════════════════════════════════════
# Coverage Cross-Reference
# ═══════════════════════════════════════════════════════════════════


class TestCoverageCrossReference:
    def test_flags_suite_with_zero_coverage(self):
        """A suite with available checks but none ran gets flagged."""
        advisor = _make_advisor(
            completed={"dns_enumeration"},
            all_check_names={"dns_enumeration", "llm_endpoint_discovery"},
            check_metadata={},
        )
        recs = advisor.analyze()
        coverage_recs = [r for r in recs if r.category == "config_suggestion"]
        # ai suite has 0 coverage (llm_endpoint_discovery is AI)
        ai_recs = [r for r in coverage_recs if "ai" in r.reason.lower()]
        assert len(ai_recs) >= 1

    def test_no_flag_when_suite_has_coverage(self):
        """A suite with sufficient coverage is not flagged."""
        # Run enough network checks to exceed threshold (3)
        advisor = _make_advisor(
            completed={"dns_enumeration", "port_scan", "tls_analysis", "service_probe"},
            all_check_names={"dns_enumeration", "port_scan", "tls_analysis", "service_probe"},
            check_metadata={},
        )
        recs = advisor.analyze()
        coverage_recs = [
            r for r in recs if r.category == "config_suggestion" and "network" in r.reason.lower()
        ]
        assert len(coverage_recs) == 0


# ═══════════════════════════════════════════════════════════════════
# Malformed / Missing Metadata
# ═══════════════════════════════════════════════════════════════════


class TestMalformedMetadata:
    def test_missing_conditions_key_does_not_crash(self):
        """check_metadata with missing 'conditions' key should not raise."""
        advisor = _make_advisor(
            completed=set(),
            all_check_names={"bad_check"},
            check_metadata={"bad_check": {"produces": ["stuff"]}},
        )
        recs = advisor.analyze()
        # Should not crash; bad_check may or may not produce a recommendation
        assert isinstance(recs, list)

    def test_empty_metadata_dict_does_not_crash(self):
        """An empty metadata dict for a check should not raise."""
        advisor = _make_advisor(
            completed=set(),
            all_check_names={"empty_meta"},
            check_metadata={"empty_meta": {}},
        )
        recs = advisor.analyze()
        assert isinstance(recs, list)

    def test_none_conditions_does_not_crash(self):
        """conditions=None should be handled gracefully."""
        advisor = _make_advisor(
            completed=set(),
            all_check_names={"null_cond"},
            check_metadata={"null_cond": {"conditions": None, "produces": []}},
        )
        recs = advisor.analyze()
        assert isinstance(recs, list)


# ═══════════════════════════════════════════════════════════════════
# Deduplication
# ═══════════════════════════════════════════════════════════════════


class TestDeduplication:
    def test_deduplicates_by_check_name(self):
        """If multiple rules produce recommendations for the same check, keep first."""
        advisor = _make_advisor(
            completed=set(),
            failed={"prompt_leakage"},
            all_check_names={"llm_endpoint_discovery", "prompt_leakage"},
            observations=[{"check_name": "llm_endpoint_discovery", "title": "Found LLM"}],
            check_metadata={
                "prompt_leakage": {"conditions": ["chat_endpoints truthy"], "produces": []},
            },
        )
        recs = advisor.analyze()
        prompt_recs = [r for r in recs if r.check_name == "prompt_leakage"]
        # Should be exactly 1 after dedup
        assert len(prompt_recs) == 1
