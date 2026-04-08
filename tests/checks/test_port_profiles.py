"""
Tests for port profiles and port resolution logic.

Covers:
- Structural invariants of profiles (sorted, no duplicates, non-empty, valid ports)
- Profile hierarchy (each profile is a superset of the previous)
- resolve_ports() with profile selection, in_scope_ports filtering, and edge cases
- PortScanCheck port resolution from config and context
"""

from unittest.mock import MagicMock, patch

from app.checks.network.port_profiles import (
    DEFAULT_PROFILE,
    PROFILES,
    resolve_ports,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Profile Structural Invariants
# ═══════════════════════════════════════════════════════════════════════════════


class TestProfileInvariants:
    """Verify structural properties that the scan logic depends on."""

    def test_all_profiles_are_sorted(self):
        for name, ports in PROFILES.items():
            assert ports == sorted(ports), f"Profile {name!r} is not sorted"

    def test_no_duplicates_in_any_profile(self):
        for name, ports in PROFILES.items():
            assert len(ports) == len(set(ports)), f"Duplicates in profile {name!r}"

    def test_all_profiles_are_non_empty(self):
        for name, ports in PROFILES.items():
            assert len(ports) > 0, f"Profile {name!r} is empty"

    def test_all_ports_are_valid_tcp_range(self):
        for name, ports in PROFILES.items():
            for port in ports:
                assert 1 <= port <= 65535, (
                    f"Port {port} in profile {name!r} outside valid TCP range"
                )

    def test_default_profile_exists_in_profiles(self):
        assert DEFAULT_PROFILE in PROFILES, (
            f"DEFAULT_PROFILE {DEFAULT_PROFILE!r} not found in PROFILES"
        )

    def test_profile_hierarchy_is_cumulative(self):
        """Each successive profile is a superset of the previous one."""
        hierarchy = ["web", "ai", "full", "lab"]
        for i in range(1, len(hierarchy)):
            smaller = set(PROFILES[hierarchy[i - 1]])
            larger = set(PROFILES[hierarchy[i]])
            assert smaller.issubset(larger), (
                f"{hierarchy[i - 1]!r} is not a subset of {hierarchy[i]!r}; "
                f"missing: {smaller - larger}"
            )

    def test_expected_profile_names_exist(self):
        """The four documented profile names must be present."""
        for name in ("web", "ai", "full", "lab"):
            assert name in PROFILES, f"Expected profile {name!r} missing"


# ═══════════════════════════════════════════════════════════════════════════════
# resolve_ports()
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolvePorts:
    """Tests for the resolve_ports() function."""

    def test_default_returns_default_profile(self):
        ports = resolve_ports()
        assert ports == PROFILES[DEFAULT_PROFILE]

    def test_explicit_profile(self):
        ports = resolve_ports(profile="web")
        assert ports == PROFILES["web"]

    def test_unknown_profile_falls_back_to_default(self):
        ports = resolve_ports(profile="nonexistent")
        assert ports == PROFILES[DEFAULT_PROFILE]

    def test_empty_string_profile_falls_back_to_default(self):
        """Empty string is falsy, so it should use the default profile."""
        ports = resolve_ports(profile="")
        assert ports == PROFILES[DEFAULT_PROFILE]

    def test_none_profile_falls_back_to_default(self):
        ports = resolve_ports(profile=None)
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

    def test_in_scope_with_single_matching_port(self):
        """Filtering down to exactly one port should work."""
        ports = resolve_ports(profile="web", in_scope_ports=[80])
        assert ports == [80]

    def test_each_profile_resolves_correctly(self):
        """Every named profile resolves to its expected port list."""
        for name, expected in PROFILES.items():
            result = resolve_ports(profile=name)
            assert result == expected, f"resolve_ports(profile={name!r}) mismatch"


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
