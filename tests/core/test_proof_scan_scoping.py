"""
Tests for `scan_id` on traffic and violation records — Phase 57.2, doc §0.5
item 5 (the F-3 gap).

57.1a gave these logs a workspace home; they still carried no scan id, so
concurrent scans pooled into one undifferentiated file and no compliance report
could honestly claim to describe a single scan. These tests are about that:
records carry the scan that made them, readers can narrow to it, and an
unscoped read still aggregates — which is the right answer for a
workspace-wide review and the wrong one for "what did this scan send".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.gates.guardian import Guardian
from app.proof_of_scope import (
    ComplianceReporter,
    ProofOfScopeSettings,
    ScanWindow,
    TrafficLogger,
    ViolationLogger,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def traffic(tmp_path):
    return TrafficLogger(data_dir=tmp_path)


@pytest.fixture
def violations(tmp_path):
    return ViolationLogger(data_dir=tmp_path)


class TestTrafficScoping:
    def test_a_request_records_the_scan_that_made_it(self, traffic):
        entry = traffic.log_request("acme.test", scan_id="scan-1")
        assert entry.scan_id == "scan-1"

    def test_entries_narrow_to_one_scan(self, traffic):
        traffic.log_request("a.test", scan_id="scan-1")
        traffic.log_request("b.test", scan_id="scan-2")
        traffic.log_request("c.test", scan_id="scan-1")

        hosts = [e["dst_host"] for e in traffic.get_entries(scan_id="scan-1")]
        assert hosts == ["a.test", "c.test"]

    def test_an_unscoped_read_still_aggregates(self, traffic):
        traffic.log_request("a.test", scan_id="scan-1")
        traffic.log_request("b.test", scan_id="scan-2")
        assert len(traffic.get_entries()) == 2

    def test_the_limit_counts_matching_entries(self, traffic):
        """Not entries scanned — a filter that trips the limit on other scans'
        rows would silently under-report."""
        for _ in range(5):
            traffic.log_request("noise.test", scan_id="other")
        for i in range(3):
            traffic.log_request(f"h{i}.test", scan_id="scan-1")

        assert len(traffic.get_entries(limit=3, scan_id="scan-1")) == 3

    def test_a_tool_call_records_the_scan(self, traffic):
        entry = traffic.log_tool_call("nmap", scan_id="scan-1")
        assert entry.scan_id == "scan-1"

    def test_operator_level_records_carry_no_scan(self, traffic):
        """Scope prep happens before any scan exists."""
        assert traffic.log_request("acme.test").scan_id is None


class TestViolationScoping:
    def test_violations_narrow_to_one_scan(self, violations):
        violations.log_violation("out_of_scope", reason="a", scan_id="scan-1")
        violations.log_violation("out_of_scope", reason="b", scan_id="scan-2")

        found = violations.get_violations(scan_id="scan-2")
        assert [v.reason for v in found] == ["b"]

    def test_an_unscoped_read_still_aggregates(self, violations):
        violations.log_violation("out_of_scope", reason="a", scan_id="scan-1")
        violations.log_violation("out_of_scope", reason="b")
        assert len(violations.get_violations()) == 2


def closed_window() -> ScanWindow:
    """A scan window that ended two days ago."""
    past = datetime.now(UTC) - timedelta(days=2)
    return ScanWindow(start=(past - timedelta(hours=1)).isoformat(), end=past.isoformat())


class TestGuardianStampsItsScan:
    """Guardian is the single chokepoint for scan allow/block decisions, so it
    is where a window violation learns which scan it belongs to."""

    def test_from_scope_carries_the_scan_id(self):
        assert Guardian.from_scope("acme.test", scan_id="scan-1").scan_id == "scan-1"

    def test_a_blocked_window_records_the_scan(self, monkeypatch, violations):
        import app.gates.guardian.gate as gate_module

        monkeypatch.setattr(gate_module, "violation_logger", violations)
        guardian = Guardian.from_scope("acme.test", scan_id="scan-1")

        allowed, _ = guardian.check_scan_window(closed_window())

        assert allowed is False
        (violation,) = violations.get_violations()
        assert violation.scan_id == "scan-1"

    def test_an_acknowledged_window_also_records_the_scan(self, monkeypatch, violations):
        import app.gates.guardian.gate as gate_module

        monkeypatch.setattr(gate_module, "violation_logger", violations)
        guardian = Guardian.from_scope("acme.test", scan_id="scan-1")

        allowed, _ = guardian.check_scan_window(closed_window(), acknowledged=True)

        assert allowed is True
        (violation,) = violations.get_violations()
        assert violation.scan_id == "scan-1"
        assert violation.user_acknowledged is True

    def test_a_guardian_built_before_a_scan_id_stamps_nothing(self):
        """The pre-flight window gate in the scan route runs before the id is
        minted; a null there is honest, not a bug."""
        assert Guardian.from_scope("acme.test").scan_id is None


class TestComplianceReportIsScoped:
    def test_the_report_counts_only_its_own_scan(self, tmp_path, traffic, violations):
        reporter = ComplianceReporter(traffic, violations, data_dir=tmp_path)
        traffic.log_request("a.test", scan_id="scan-1")
        traffic.log_request("b.test", scan_id="scan-2")
        traffic.log_request("c.test", scan_id="scan-2")
        violations.log_violation("out_of_scope", reason="a", scan_id="scan-2")

        report = reporter.generate_report(
            session_id="sess-1",
            target="acme.test",
            exclusions=[],
            proof_settings=ProofOfScopeSettings(),
            scan_id="scan-1",
        )

        assert report.total_requests == 1
        assert report.violations == []

    def test_an_unscoped_report_still_aggregates(self, tmp_path, traffic, violations):
        """The honest answer for a workspace-wide report."""
        reporter = ComplianceReporter(traffic, violations, data_dir=tmp_path)
        traffic.log_request("a.test", scan_id="scan-1")
        traffic.log_request("b.test", scan_id="scan-2")

        report = reporter.generate_report(
            session_id="sess-1",
            target="acme.test",
            exclusions=[],
            proof_settings=ProofOfScopeSettings(),
        )

        assert report.total_requests == 2
