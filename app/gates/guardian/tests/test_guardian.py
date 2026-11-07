"""
Tests for app/gates/guardian/gate.py

Folder-shape discovery/config tests plus the Guardian behavior tests relocated
here from tests/scanning/test_proof_of_scope_ops.py in 56.12 (the proof-of-scope
logging/report tests stay there; the gate's own enforcement tests co-locate).
"""

import pytest

from app.components.config_models import ComponentConfig
from app.gates.base import BaseGate
from app.gates.guardian.gate import Guardian
from app.gates.registry import discover_gate_specs
from app.proof_of_scope import ScanWindow

pytestmark = pytest.mark.unit


# ═══════════════════════════════════════════════════════════════════
# Discovery + Config Resolution
# ═══════════════════════════════════════════════════════════════════


class TestDiscoveryAndConfig:
    def test_guardian_is_discovered(self):
        registry = discover_gate_specs()
        assert "guardian" in registry.names()

    def test_enabled_by_default(self):
        registry = discover_gate_specs()
        assert registry.config("guardian").enabled is True

    def test_entry_class_is_basegate(self):
        registry = discover_gate_specs()
        cls = registry.entry_cls("guardian")
        assert cls is Guardian
        assert issubclass(cls, BaseGate)

    def test_enforces_metadata(self):
        registry = discover_gate_specs()
        contract = registry.get("guardian").contract
        assert set(contract.enforces) == {"scope", "scan_window", "technique"}

    def test_param_accessor_reads_config_yaml(self):
        registry = discover_gate_specs()
        assert registry.param("guardian", "block_exclusions") is True
        assert registry.param("guardian", "log_violations") is True
        assert registry.param("guardian", "missing", "fallback") == "fallback"

    def test_param_unknown_gate_returns_default(self):
        registry = discover_gate_specs()
        assert registry.param("nope", "block_exclusions", "x") == "x"

    def test_config_reads_parameters(self):
        comp = ComponentConfig(enabled=False, parameters={"block_exclusions": False})
        assert comp.enabled is False
        assert comp.parameters["block_exclusions"] is False


# ═══════════════════════════════════════════════════════════════════
# Guardian URL / technique scope enforcement (replaces ScopeChecker)
# ═══════════════════════════════════════════════════════════════════


class TestGuardianUrlScope:
    """Tests for Guardian URL scope enforcement (replaces ScopeChecker)."""

    def test_exact_match(self):
        """Exact domain match."""
        g = Guardian.from_scope("example.com")

        ok, _ = g.check_url("http://example.com/path")
        assert ok is True

        ok, _ = g.check_url("http://other.com/path")
        assert ok is False

    def test_wildcard_match(self):
        """Wildcard pattern match."""
        g = Guardian.from_scope("*.example.com")

        ok, _ = g.check_url("http://api.example.com/")
        assert ok is True

        ok, _ = g.check_url("http://sub.api.example.com/")
        assert ok is True

        ok, _ = g.check_url("http://other.com/")
        assert ok is False

    def test_exclusions(self):
        """Exclusions override scope."""
        g = Guardian.from_scope("*.example.com", exclude=["admin.example.com"])

        ok, _ = g.check_url("http://api.example.com/")
        assert ok is True

        ok, _ = g.check_url("http://admin.example.com/")
        assert ok is False

    def test_multiple_exclusions(self):
        """Multiple exclusion patterns."""
        g = Guardian.from_scope(
            "*.example.com",
            exclude=["admin.example.com", "internal.example.com"],
        )

        ok, _ = g.check_url("http://admin.example.com/")
        assert ok is False

        ok, _ = g.check_url("http://internal.example.com/")
        assert ok is False

        ok, _ = g.check_url("http://api.example.com/")
        assert ok is True

    def test_url_scope_validator_callback(self):
        """url_scope_validator works as a BaseCheck scope_validator callback."""
        g = Guardian.from_scope("example.com")

        assert g.url_scope_validator("http://example.com/test") is True
        assert g.url_scope_validator("http://evil.com/test") is False
        assert g.violation_count == 1

    def test_forbidden_technique(self):
        """Forbidden techniques are blocked."""
        g = Guardian.from_scope("example.com", forbidden_techniques=["dangerous_check"])

        ok, reason = g.check_technique("dangerous_check")
        assert ok is False
        assert "forbidden" in reason

        ok, _ = g.check_technique("safe_check")
        assert ok is True


# ═══════════════════════════════════════════════════════════════════
# Guardian scan-window gate
# ═══════════════════════════════════════════════════════════════════


class TestGuardianScanWindow:
    """Tests for Guardian.check_scan_window gate."""

    def test_no_window_configured(self):
        g = Guardian.from_scope("example.com")
        ok, _ = g.check_scan_window(ScanWindow())
        assert ok is True

    def test_within_window(self):
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        window = ScanWindow(
            start=(now - timedelta(hours=1)).isoformat(),
            end=(now + timedelta(hours=1)).isoformat(),
        )
        g = Guardian.from_scope("example.com")
        ok, _ = g.check_scan_window(window)
        assert ok is True

    def test_outside_window_blocks(self, tmp_path, monkeypatch):
        from datetime import UTC, datetime, timedelta

        from app import proof_of_scope as pos

        # 57.1a: `_data_dir` / `_log_file` are derived properties now (they
        # resolve the workspace lazily), so point the seam they derive from.
        monkeypatch.setattr(pos.violation_logger, "_explicit_dir", tmp_path)

        past = datetime.now(UTC) - timedelta(days=2)
        window = ScanWindow(
            start=(past - timedelta(hours=1)).isoformat(),
            end=past.isoformat(),
        )
        g = Guardian.from_scope("example.com")
        ok, reason = g.check_scan_window(window, acknowledged=False)
        assert ok is False
        assert "outside" in reason.lower()

    def test_outside_window_with_ack_allowed(self, tmp_path, monkeypatch):
        from datetime import UTC, datetime, timedelta

        from app import proof_of_scope as pos

        # 57.1a: `_data_dir` / `_log_file` are derived properties now (they
        # resolve the workspace lazily), so point the seam they derive from.
        monkeypatch.setattr(pos.violation_logger, "_explicit_dir", tmp_path)

        past = datetime.now(UTC) - timedelta(days=2)
        window = ScanWindow(
            start=(past - timedelta(hours=1)).isoformat(),
            end=past.isoformat(),
        )
        g = Guardian.from_scope("example.com")
        ok, _ = g.check_scan_window(window, acknowledged=True)
        assert ok is True
