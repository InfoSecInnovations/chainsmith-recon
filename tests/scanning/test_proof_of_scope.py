"""Tests for proof-of-scope data types and settings."""

from datetime import UTC, datetime, timedelta

import pytest

from app.proof_of_scope import (
    ProofOfScopeSettings,
    ScanWindow,
    ScopeStatus,
    TrafficEntry,
    TrafficEntryType,
    ViolationEntry,
)

# Note: TrafficEntryType and ScopeStatus are used by TrafficEntry/ViolationEntry tests below

pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# TrafficEntry Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTrafficEntry:
    """Tests for TrafficEntry model."""

    def test_minimal_entry(self):
        """Minimal entry with required fields."""
        entry = TrafficEntry(
            timestamp="2024-01-01T00:00:00Z",
            entry_type=TrafficEntryType.HTTP_REQUEST,
        )

        assert entry.timestamp == "2024-01-01T00:00:00Z"
        assert entry.entry_type == TrafficEntryType.HTTP_REQUEST
        assert entry.dst_host is None
        assert entry.scope_status == ScopeStatus.UNKNOWN

    def test_full_entry(self):
        """Full entry with all fields."""
        entry = TrafficEntry(
            timestamp="2024-01-01T00:00:00Z",
            entry_type=TrafficEntryType.HTTP_REQUEST,
            dst_host="example.com",
            dst_ip="192.168.1.1",
            dst_port=443,
            protocol="HTTPS",
            method="GET",
            path="/api/v1/test",
            check_name="header_check",
            tool_name="http_client",
            scope_status=ScopeStatus.IN_SCOPE,
            status_code=200,
            response_time_ms=150.5,
        )

        assert entry.dst_host == "example.com"
        assert entry.dst_port == 443
        assert entry.status_code == 200
        assert entry.response_time_ms == 150.5


# ═══════════════════════════════════════════════════════════════════════════════
# ViolationEntry Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestViolationEntry:
    """Tests for ViolationEntry model."""

    def test_minimal_entry(self):
        """Minimal entry with required fields."""
        entry = ViolationEntry(
            timestamp="2024-01-01T00:00:00Z",
            violation_type="out_of_scope",
            reason="Host not in target scope",
        )

        assert entry.violation_type == "out_of_scope"
        assert entry.reason == "Host not in target scope"
        assert entry.blocked is False

    def test_full_entry(self):
        """Full entry with all fields."""
        entry = ViolationEntry(
            timestamp="2024-01-01T00:00:00Z",
            violation_type="excluded_target",
            target_host="admin.example.com",
            target_path="/admin",
            check_name="path_probe",
            tool_name="http_client",
            reason="Host in exclusion list",
            blocked=True,
            user_acknowledged=False,
        )

        assert entry.target_host == "admin.example.com"
        assert entry.blocked is True


# ═══════════════════════════════════════════════════════════════════════════════
# ScanWindow Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestScanWindow:
    """Tests for ScanWindow model."""

    def test_no_window_configured(self):
        """No window means not configured."""
        window = ScanWindow()

        assert window.is_configured() is False
        assert window.is_within_window() is True  # No restrictions

    def test_start_only(self):
        """Window with only start time."""
        # Future start - not yet within window
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        window = ScanWindow(start=future)

        assert window.is_configured() is True
        assert window.is_within_window() is False

        # Past start - within window
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        window = ScanWindow(start=past)

        assert window.is_within_window() is True

    def test_end_only(self):
        """Window with only end time."""
        # Future end - within window
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        window = ScanWindow(end=future)

        assert window.is_configured() is True
        assert window.is_within_window() is True

        # Past end - outside window
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        window = ScanWindow(end=past)

        assert window.is_within_window() is False

    def test_start_and_end(self):
        """Window with both start and end."""
        past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        window = ScanWindow(start=past, end=future)

        assert window.is_configured() is True
        assert window.is_within_window() is True

    def test_handles_z_suffix(self):
        """Handles ISO timestamps with Z suffix."""
        past = (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        window = ScanWindow(start=past)

        assert window.is_within_window() is True


# ═══════════════════════════════════════════════════════════════════════════════
# ProofOfScopeSettings Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestProofOfScopeSettings:
    """Tests for ProofOfScopeSettings model."""

    def test_defaults(self):
        """Default settings."""
        settings = ProofOfScopeSettings()

        assert settings.traffic_logging is True
        assert settings.block_exclusions is True
        assert settings.log_violations is True
        assert settings.outside_window_acknowledged is False

    def test_custom_settings(self):
        """Custom settings."""
        settings = ProofOfScopeSettings(
            traffic_logging=False,
            block_exclusions=False,
            scan_window=ScanWindow(start="2024-01-01T00:00:00Z"),
            outside_window_acknowledged=True,
            outside_window_acknowledged_at="2024-01-01T00:00:00Z",
        )

        assert settings.traffic_logging is False
        assert settings.scan_window.is_configured() is True
        assert settings.outside_window_acknowledged is True
