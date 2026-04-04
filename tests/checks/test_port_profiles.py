"""
Tests for port profiles and port resolution logic.

Covers:
- Port category constants (WEB, API, AI, DATA, LAB)
- Named profiles (web, ai, full, lab)
- resolve_ports() with profile selection and in_scope_ports filtering
- PortScanCheck port resolution from config and context
"""

from unittest.mock import MagicMock, patch

from app.checks.network.port_profiles import (
    AI,
    API,
    DATA,
    DEFAULT_PROFILE,
    LAB,
    PROFILES,
    WEB,
    resolve_ports,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Port Constants
# ═══════════════════════════════════════════════════════════════════════════════


class TestPortConstants:
    """Verify port category lists contain expected entries."""

    def test_web_has_standard_ports(self):
        assert 80 in WEB
        assert 443 in WEB
        assert 8080 in WEB

    def test_api_has_gateway_ports(self):
        assert 4000 in API  # LiteLLM
        assert 8001 in API  # Kong

    def test_ai_has_ml_ports(self):
        assert 11434 in AI  # Ollama
        assert 7860 in AI  # Gradio
        assert 8501 in AI  # Streamlit

    def test_data_has_db_ports(self):
        assert 5432 in DATA  # PostgreSQL
        assert 3306 in DATA  # MySQL
        assert 6379 in DATA  # Redis

    def test_lab_has_container_ports(self):
        assert 8081 in LAB
        assert 8089 in LAB
        assert 5173 in LAB  # Vite

    def test_no_duplicates_within_categories(self):
        for name, ports in [("WEB", WEB), ("API", API), ("AI", AI), ("DATA", DATA), ("LAB", LAB)]:
            assert len(ports) == len(set(ports)), f"Duplicates in {name}"


# ═══════════════════════════════════════════════════════════════════════════════
# Named Profiles
# ═══════════════════════════════════════════════════════════════════════════════


class TestProfiles:
    """Verify named profiles contain the right categories."""

    def test_web_profile_includes_web_and_api(self):
        profile = PROFILES["web"]
        for port in WEB + API:
            assert port in profile

    def test_ai_profile_includes_ai_ports(self):
        profile = PROFILES["ai"]
        for port in AI:
            assert port in profile

    def test_full_profile_includes_data(self):
        profile = PROFILES["full"]
        for port in DATA:
            assert port in profile

    def test_lab_profile_is_superset(self):
        """Lab profile includes everything."""
        lab = set(PROFILES["lab"])
        for name in ["web", "ai", "full"]:
            assert set(PROFILES[name]).issubset(lab), f"{name} not subset of lab"

    def test_profiles_are_sorted(self):
        for name, ports in PROFILES.items():
            assert ports == sorted(ports), f"Profile {name} not sorted"

    def test_default_profile_is_lab(self):
        assert DEFAULT_PROFILE == "lab"


# ═══════════════════════════════════════════════════════════════════════════════
# resolve_ports()
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolvePorts:
    """Tests for the resolve_ports() function."""

    def test_default_returns_lab(self):
        ports = resolve_ports()
        assert ports == PROFILES["lab"]

    def test_explicit_profile(self):
        ports = resolve_ports(profile="web")
        assert ports == PROFILES["web"]

    def test_unknown_profile_falls_back_to_default(self):
        ports = resolve_ports(profile="nonexistent")
        assert ports == PROFILES[DEFAULT_PROFILE]

    def test_in_scope_ports_filters(self):
        """in_scope_ports intersects with profile."""
        ports = resolve_ports(profile="lab", in_scope_ports=[80, 443, 9999])
        assert 80 in ports
        assert 443 in ports
        assert 9999 not in ports  # Not in any profile
        assert 8080 not in ports  # In profile but not in in_scope_ports

    def test_empty_in_scope_ports_means_no_restriction(self):
        """Empty list = no filter applied."""
        ports = resolve_ports(profile="web", in_scope_ports=[])
        assert ports == PROFILES["web"]

    def test_in_scope_ports_result_is_sorted(self):
        ports = resolve_ports(profile="lab", in_scope_ports=[8080, 80, 443])
        assert ports == sorted(ports)

    def test_in_scope_ports_disjoint_returns_empty(self):
        """If in_scope_ports has no overlap with profile, result is empty."""
        ports = resolve_ports(profile="web", in_scope_ports=[12345, 54321])
        assert ports == []


# ═══════════════════════════════════════════════════════════════════════════════
# PortScanCheck Port Resolution
# ═══════════════════════════════════════════════════════════════════════════════


class TestPortScanCheckResolution:
    """Tests for PortScanCheck._resolve_ports() integration with config."""

    def _make_config(self, port_profile="lab", in_scope_ports=None):
        """Create a mock config."""
        cfg = MagicMock()
        cfg.scope.port_profile = port_profile
        cfg.scope.in_scope_ports = in_scope_ports or []
        return cfg

    @patch("app.checks.network.ports.get_config")
    def test_uses_config_profile(self, mock_get_config):
        from app.checks.network.ports import PortScanCheck

        mock_get_config.return_value = self._make_config(port_profile="web")

        check = PortScanCheck()
        ports = check._resolve_ports({})

        assert ports == PROFILES["web"]

    @patch("app.checks.network.ports.get_config")
    def test_context_overrides_config_profile(self, mock_get_config):
        from app.checks.network.ports import PortScanCheck

        mock_get_config.return_value = self._make_config(port_profile="web")

        check = PortScanCheck()
        ports = check._resolve_ports({"port_profile": "ai"})

        assert ports == PROFILES["ai"]

    @patch("app.checks.network.ports.get_config")
    def test_explicit_profile_overrides_context(self, mock_get_config):
        from app.checks.network.ports import PortScanCheck

        mock_get_config.return_value = self._make_config(port_profile="web")

        check = PortScanCheck(profile="full")
        ports = check._resolve_ports({"port_profile": "ai"})

        assert ports == PROFILES["full"]

    @patch("app.checks.network.ports.get_config")
    def test_explicit_ports_bypass_profile(self, mock_get_config):
        from app.checks.network.ports import PortScanCheck

        mock_get_config.return_value = self._make_config()

        check = PortScanCheck(ports=[22, 80, 443])
        ports = check._resolve_ports({})

        assert ports == [22, 80, 443]

    @patch("app.checks.network.ports.get_config")
    def test_in_scope_ports_filters_profile(self, mock_get_config):
        from app.checks.network.ports import PortScanCheck

        mock_get_config.return_value = self._make_config(
            port_profile="lab",
            in_scope_ports=[80, 443],
        )

        check = PortScanCheck()
        ports = check._resolve_ports({})

        assert ports == [80, 443]

    @patch("app.checks.network.ports.get_config")
    def test_in_scope_ports_filters_explicit_ports(self, mock_get_config):
        from app.checks.network.ports import PortScanCheck

        mock_get_config.return_value = self._make_config(
            in_scope_ports=[80, 443],
        )

        check = PortScanCheck(ports=[22, 80, 443, 8080])
        ports = check._resolve_ports({})

        assert 80 in ports
        assert 443 in ports
        assert 22 not in ports
        assert 8080 not in ports
