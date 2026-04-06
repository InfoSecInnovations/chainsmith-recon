"""Tests for proof-of-scope operations and logging."""

import json
from pathlib import Path

import pytest

from app.proof_of_scope import (
    ComplianceReport,
    ComplianceReporter,
    EngagementWindow,
    ProofOfScopeSettings,
    ScopeChecker,
    ScopeStatus,
    TrafficEntry,
    TrafficEntryType,
    TrafficLogger,
    ViolationEntry,
    ViolationLogger,
)


pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# TrafficLogger Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTrafficLogger:
    """Tests for TrafficLogger class."""

    @pytest.fixture
    def logger(self, tmp_path: Path):
        """Create a logger with temp data directory."""
        return TrafficLogger(data_dir=tmp_path)

    def test_log_request(self, logger, tmp_path: Path):
        """log_request creates entry."""
        entry = logger.log_request(
            dst_host="example.com",
            method="GET",
            path="/api",
            port=443,
            scope_status=ScopeStatus.IN_SCOPE,
        )

        assert entry.dst_host == "example.com"
        assert entry.entry_type == TrafficEntryType.HTTP_REQUEST

        # Check file was written
        log_file = tmp_path / "traffic_log.jsonl"
        assert log_file.exists()

        entries = logger.get_entries()
        assert len(entries) == 1

    def test_log_request_with_response_info(self, logger):
        """log_request includes response info."""
        entry = logger.log_request(
            dst_host="example.com",
            status_code=200,
            response_time_ms=50.5,
        )

        assert entry.status_code == 200
        assert entry.response_time_ms == 50.5

    def test_log_tool_call(self, logger):
        """log_tool_call creates entry."""
        entry = logger.log_tool_call(
            tool_name="http_get",
            check_name="header_check",
            target_info={"host": "example.com", "port": 443},
        )

        assert entry.tool_name == "http_get"
        assert entry.entry_type == TrafficEntryType.TOOL_CALL
        assert entry.dst_host == "example.com"
        assert entry.scope_status == ScopeStatus.IN_SCOPE

    def test_log_tool_call_no_target(self, logger):
        """log_tool_call works without target_info."""
        entry = logger.log_tool_call(tool_name="generic_tool")

        assert entry.tool_name == "generic_tool"
        assert entry.dst_host is None

    def test_get_entries_empty(self, logger):
        """get_entries returns empty list when no log."""
        entries = logger.get_entries()
        assert entries == []

    def test_get_entries_multiple(self, logger):
        """get_entries returns multiple entries."""
        logger.log_request(dst_host="host1.com")
        logger.log_request(dst_host="host2.com")
        logger.log_request(dst_host="host3.com")

        entries = logger.get_entries()
        assert len(entries) == 3

    def test_get_entries_limit(self, logger):
        """get_entries respects limit."""
        for i in range(10):
            logger.log_request(dst_host=f"host{i}.com")

        entries = logger.get_entries(limit=5)
        assert len(entries) == 5

    def test_clear(self, logger, tmp_path: Path):
        """clear removes log file."""
        logger.log_request(dst_host="example.com")
        log_file = tmp_path / "traffic_log.jsonl"
        assert log_file.exists()

        logger.clear()
        assert not log_file.exists()

    def test_clear_nonexistent(self, logger):
        """clear handles missing file."""
        logger.clear()  # Should not raise


# ═══════════════════════════════════════════════════════════════════════════════
# ViolationLogger Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestViolationLogger:
    """Tests for ViolationLogger class."""

    @pytest.fixture
    def logger(self, tmp_path: Path):
        """Create a logger with temp data directory."""
        return ViolationLogger(data_dir=tmp_path)

    def test_log_violation(self, logger, tmp_path: Path):
        """log_violation creates entry."""
        entry = logger.log_violation(
            violation_type="out_of_scope",
            reason="Host not in scope",
            target_host="external.com",
        )

        assert entry.violation_type == "out_of_scope"
        assert entry.target_host == "external.com"

        # Check file was written
        log_file = tmp_path / "violations_log.jsonl"
        assert log_file.exists()

    def test_log_violation_full(self, logger):
        """log_violation with all fields."""
        entry = logger.log_violation(
            violation_type="excluded_target",
            reason="Host in exclusion list",
            target_host="admin.example.com",
            target_path="/admin",
            check_name="path_probe",
            tool_name="http_client",
            blocked=True,
            user_acknowledged=True,
        )

        assert entry.blocked is True
        assert entry.user_acknowledged is True

    def test_get_violations_empty(self, logger):
        """get_violations returns empty list when no log."""
        violations = logger.get_violations()
        assert violations == []

    def test_get_violations_multiple(self, logger):
        """get_violations returns all violations."""
        logger.log_violation(violation_type="type1", reason="reason1")
        logger.log_violation(violation_type="type2", reason="reason2")

        violations = logger.get_violations()
        assert len(violations) == 2
        assert all(isinstance(v, ViolationEntry) for v in violations)

    def test_clear(self, logger, tmp_path: Path):
        """clear removes log file."""
        logger.log_violation(violation_type="test", reason="test")
        log_file = tmp_path / "violations_log.jsonl"
        assert log_file.exists()

        logger.clear()
        assert not log_file.exists()


# ═══════════════════════════════════════════════════════════════════════════════
# ComplianceReporter Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestComplianceReporter:
    """Tests for ComplianceReporter class."""

    @pytest.fixture
    def setup_reporter(self, tmp_path: Path):
        """Create reporter with temp data directory."""
        traffic = TrafficLogger(data_dir=tmp_path)
        violations = ViolationLogger(data_dir=tmp_path)
        reporter = ComplianceReporter(traffic, violations, data_dir=tmp_path)

        return reporter, traffic, violations, tmp_path

    def test_generate_report_empty(self, setup_reporter):
        """Generate report with no traffic or violations."""
        reporter, _, _, _ = setup_reporter

        settings = ProofOfScopeSettings()
        report = reporter.generate_report(
            session_id="test-session",
            target="example.com",
            exclusions=["admin.example.com"],
            proof_settings=settings,
        )

        assert report.session_id == "test-session"
        assert report.target == "example.com"
        assert report.total_requests == 0
        assert report.violations == []

    def test_generate_report_with_traffic(self, setup_reporter):
        """Generate report with traffic entries."""
        reporter, traffic, _, _ = setup_reporter

        # Log some traffic
        traffic.log_request(dst_host="example.com", scope_status=ScopeStatus.IN_SCOPE)
        traffic.log_request(dst_host="example.com", scope_status=ScopeStatus.IN_SCOPE)
        traffic.log_request(dst_host="other.com", scope_status=ScopeStatus.OUT_OF_SCOPE)

        settings = ProofOfScopeSettings()
        report = reporter.generate_report(
            session_id="test",
            target="example.com",
            exclusions=[],
            proof_settings=settings,
        )

        assert report.total_requests == 3
        assert report.in_scope_requests == 2
        assert report.out_of_scope_attempts == 1

    def test_generate_report_with_violations(self, setup_reporter):
        """Generate report includes violations."""
        reporter, _, violations, _ = setup_reporter

        violations.log_violation(violation_type="out_of_scope", reason="test")

        settings = ProofOfScopeSettings()
        report = reporter.generate_report(
            session_id="test",
            target="example.com",
            exclusions=[],
            proof_settings=settings,
        )

        assert len(report.violations) == 1

    def test_generate_report_saves_file(self, setup_reporter):
        """generate_report saves to file."""
        reporter, _, _, tmp_path = setup_reporter

        settings = ProofOfScopeSettings()
        reporter.generate_report(
            session_id="test",
            target="example.com",
            exclusions=[],
            proof_settings=settings,
        )

        report_file = tmp_path / "compliance_report.json"
        assert report_file.exists()

        # Verify JSON is valid
        data = json.loads(report_file.read_text())
        assert data["session_id"] == "test"

    def test_get_latest_report(self, setup_reporter):
        """get_latest_report returns saved report."""
        reporter, _, _, _ = setup_reporter

        settings = ProofOfScopeSettings()
        original = reporter.generate_report(
            session_id="test-session",
            target="example.com",
            exclusions=[],
            proof_settings=settings,
        )

        loaded = reporter.get_latest_report()

        assert loaded is not None
        assert loaded.session_id == original.session_id

    def test_get_latest_report_none(self, setup_reporter):
        """get_latest_report returns None if no report."""
        reporter, _, _, _ = setup_reporter

        report = reporter.get_latest_report()
        assert report is None


# ═══════════════════════════════════════════════════════════════════════════════
# ScopeChecker Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestScopeChecker:
    """Tests for ScopeChecker class."""

    def test_exact_match(self):
        """Exact domain match."""
        checker = ScopeChecker("example.com", exclusions=[])

        assert checker.check_host("example.com") == ScopeStatus.IN_SCOPE
        assert checker.check_host("EXAMPLE.COM") == ScopeStatus.IN_SCOPE  # Case insensitive
        assert checker.check_host("other.com") == ScopeStatus.OUT_OF_SCOPE

    def test_wildcard_match(self):
        """Wildcard pattern match."""
        checker = ScopeChecker("*.example.com", exclusions=[])

        assert checker.check_host("api.example.com") == ScopeStatus.IN_SCOPE
        assert checker.check_host("sub.api.example.com") == ScopeStatus.IN_SCOPE
        assert checker.check_host("example.com") == ScopeStatus.IN_SCOPE  # Base domain too
        assert checker.check_host("other.com") == ScopeStatus.OUT_OF_SCOPE

    def test_exclusions(self):
        """Exclusions override scope."""
        checker = ScopeChecker("*.example.com", exclusions=["admin.example.com"])

        assert checker.check_host("api.example.com") == ScopeStatus.IN_SCOPE
        assert checker.check_host("admin.example.com") == ScopeStatus.EXCLUDED

    def test_exclusion_substring_match(self):
        """Exclusions use substring matching."""
        checker = ScopeChecker("*.example.com", exclusions=["admin"])

        # Contains "admin"
        assert checker.check_host("admin.example.com") == ScopeStatus.EXCLUDED
        assert checker.check_host("my-admin-panel.example.com") == ScopeStatus.EXCLUDED

    def test_is_excluded(self):
        """is_excluded helper method."""
        checker = ScopeChecker("*.example.com", exclusions=["admin.example.com"])

        assert checker.is_excluded("admin.example.com") is True
        assert checker.is_excluded("api.example.com") is False

    def test_multiple_exclusions(self):
        """Multiple exclusion patterns."""
        checker = ScopeChecker(
            "*.example.com",
            exclusions=["admin.example.com", "internal.example.com"],
        )

        assert checker.check_host("admin.example.com") == ScopeStatus.EXCLUDED
        assert checker.check_host("internal.example.com") == ScopeStatus.EXCLUDED
        assert checker.check_host("api.example.com") == ScopeStatus.IN_SCOPE


# ═══════════════════════════════════════════════════════════════════════════════
# ComplianceReport Model Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestComplianceReport:
    """Tests for ComplianceReport model."""

    def test_create_report(self):
        """Create a compliance report."""
        settings = ProofOfScopeSettings()
        report = ComplianceReport(
            generated_at="2024-01-01T00:00:00Z",
            session_id="test-session",
            engagement_window=EngagementWindow(),
            target="example.com",
            exclusions=["admin.example.com"],
            total_requests=100,
            in_scope_requests=95,
            out_of_scope_attempts=5,
            blocked_requests=3,
            violations=[],
            proof_settings=settings,
        )

        assert report.session_id == "test-session"
        assert report.total_requests == 100
        assert report.in_scope_requests == 95

    def test_report_with_violations(self):
        """Report includes violation entries."""
        violation = ViolationEntry(
            timestamp="2024-01-01T00:00:00Z",
            violation_type="out_of_scope",
            reason="test",
        )

        settings = ProofOfScopeSettings()
        report = ComplianceReport(
            generated_at="2024-01-01T00:00:00Z",
            session_id="test",
            engagement_window=EngagementWindow(),
            target="example.com",
            exclusions=[],
            violations=[violation],
            proof_settings=settings,
        )

        assert len(report.violations) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# reset_proof_of_scope Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestResetProofOfScope:
    """Tests for reset_proof_of_scope function."""

    def test_reset_clears_all(self, tmp_path: Path):
        """Clearing loggers removes all log and report files."""
        traffic = TrafficLogger(data_dir=tmp_path)
        violations = ViolationLogger(data_dir=tmp_path)
        reporter = ComplianceReporter(traffic, violations, data_dir=tmp_path)

        # Create files
        (tmp_path / "traffic_log.jsonl").write_text('{"test": 1}\n')
        (tmp_path / "violations_log.jsonl").write_text('{"test": 1}\n')
        (tmp_path / "compliance_report.json").write_text('{"test": 1}')

        # Clear each component (same as reset_proof_of_scope does)
        traffic.clear()
        violations.clear()
        if reporter._report_file.exists():
            reporter._report_file.unlink()

        assert not (tmp_path / "traffic_log.jsonl").exists()
        assert not (tmp_path / "violations_log.jsonl").exists()
        assert not (tmp_path / "compliance_report.json").exists()
