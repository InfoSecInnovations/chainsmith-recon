"""Tests for network_port_scan."""

from unittest.mock import MagicMock, patch

from app.checks.network.port_profiles import (
    PROFILES,
)


class TestPortScanCheckResolution:
    """Tests for PortScanCheck._resolve_ports() integration with config."""

    def _make_config(self, port_profile="lab", in_scope_ports=None):
        """Create a mock config."""
        cfg = MagicMock()
        cfg.scope.port_profile = port_profile
        cfg.scope.in_scope_ports = in_scope_ports or []
        return cfg

    @patch("app.checks.network.network_port_scan.check.get_config")
    def test_uses_config_profile(self, mock_get_config):
        from app.checks.network.network_port_scan import PortScanCheck

        mock_get_config.return_value = self._make_config(port_profile="web")

        check = PortScanCheck()
        ports = check._resolve_ports({})

        assert ports == PROFILES["web"]

    @patch("app.checks.network.network_port_scan.check.get_config")
    def test_context_overrides_config_profile(self, mock_get_config):
        from app.checks.network.network_port_scan import PortScanCheck

        mock_get_config.return_value = self._make_config(port_profile="web")

        check = PortScanCheck()
        ports = check._resolve_ports({"port_profile": "ai"})

        assert ports == PROFILES["ai"]

    @patch("app.checks.network.network_port_scan.check.get_config")
    def test_explicit_profile_overrides_context(self, mock_get_config):
        from app.checks.network.network_port_scan import PortScanCheck

        mock_get_config.return_value = self._make_config(port_profile="web")

        check = PortScanCheck(profile="full")
        ports = check._resolve_ports({"port_profile": "ai"})

        assert ports == PROFILES["full"]

    @patch("app.checks.network.network_port_scan.check.get_config")
    def test_explicit_ports_bypass_profile(self, mock_get_config):
        from app.checks.network.network_port_scan import PortScanCheck

        mock_get_config.return_value = self._make_config()

        check = PortScanCheck(ports=[22, 80, 443])
        ports = check._resolve_ports({})

        assert ports == [22, 80, 443]

    @patch("app.checks.network.network_port_scan.check.get_config")
    def test_in_scope_ports_filters_profile(self, mock_get_config):
        from app.checks.network.network_port_scan import PortScanCheck

        mock_get_config.return_value = self._make_config(
            port_profile="lab",
            in_scope_ports=[80, 443],
        )

        check = PortScanCheck()
        ports = check._resolve_ports({})

        assert ports == [80, 443]

    @patch("app.checks.network.network_port_scan.check.get_config")
    def test_in_scope_ports_filters_explicit_ports(self, mock_get_config):
        from app.checks.network.network_port_scan import PortScanCheck

        mock_get_config.return_value = self._make_config(
            in_scope_ports=[80, 443],
        )

        check = PortScanCheck(ports=[22, 80, 443, 8080])
        ports = check._resolve_ports({})

        assert 80 in ports
        assert 443 in ports
        assert 22 not in ports
        assert 8080 not in ports


async def probe_and_grade(check, context):
    """Run the probe, then the grading stage, and return the graded result.

    This check is split into probe + grade, so `run()` now
    returns candidates rather than observations. Tests assert on what an
    operator sees, which is what the grading stage produces — the same thing
    `CheckLauncher` calls immediately after `execute()`.
    """
    from app.grading import grade_result

    result = await check.run(context)
    return await grade_result(check, result, context)


def _open_connection(open_ports: set[int]):
    """A fake `asyncio.open_connection` where only `open_ports` accept."""

    async def _connect(host, port):
        if port not in open_ports:
            raise ConnectionRefusedError(f"{host}:{port} refused")
        writer = MagicMock()
        writer.close = MagicMock()

        async def _wait_closed():
            return None

        writer.wait_closed = _wait_closed
        return MagicMock(), writer

    return _connect


class TestPortScanCheckProbeAndGrade:
    """The probe records open ports; the grader states that they are open."""

    @patch("app.checks.network.network_port_scan.check.get_config")
    async def test_open_port_is_graded(self, mock_get_config):
        from app.checks.network.network_port_scan import PortScanCheck

        cfg = MagicMock()
        cfg.scope.port_profile = "lab"
        cfg.scope.in_scope_ports = []
        mock_get_config.return_value = cfg

        check = PortScanCheck(ports=[80, 9999])
        with patch("asyncio.open_connection", side_effect=_open_connection({80})):
            result = await probe_and_grade(check, {"target_hosts": ["10.0.0.1"]})

        assert len(result.services) == 1
        assert result.services[0].port == 80

        assert len(result.observations) == 1
        observation = result.observations[0]
        assert observation.title == "Open port: 10.0.0.1:80"
        assert observation.severity == "info"
        assert observation.confidence == 0.99
        assert observation.grading_state == "graded"
        # The discriminator keeps two open ports on one host distinct.
        assert observation.id == "network_port_scan-10.0.0.1-port-80"

    @patch("app.checks.network.network_port_scan.check.get_config")
    async def test_closed_ports_record_nothing(self, mock_get_config):
        from app.checks.network.network_port_scan import PortScanCheck

        cfg = MagicMock()
        cfg.scope.port_profile = "lab"
        cfg.scope.in_scope_ports = []
        mock_get_config.return_value = cfg

        check = PortScanCheck(ports=[80, 443])
        with patch("asyncio.open_connection", side_effect=_open_connection(set())):
            result = await probe_and_grade(check, {"target_hosts": ["10.0.0.1"]})

        assert result.services == []
        assert result.observations == []
