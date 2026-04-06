"""Tests for IPv6DiscoveryCheck: AAAA resolution, dual-stack analysis, and IPv6 findings."""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestIPv6DiscoveryCheckInit:
    """Test IPv6DiscoveryCheck metadata and initialization."""

    def test_check_metadata(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        assert check.name == "ipv6_discovery"
        assert "ipv6" in check.description.lower()

    def test_conditions(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "target_hosts"
        assert check.conditions[0].operator == "truthy"

    def test_produces(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        assert "ipv6_data" in check.produces

    def test_references(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        assert len(check.references) > 0

    def test_ula_prefix_defined(self):
        from app.checks.network.ipv6_discovery import ULA_PREFIX

        assert ULA_PREFIX == "fd"


class TestIPv6DiscoveryCheckRun:
    """Test IPv6DiscoveryCheck runtime behavior."""

    @pytest.mark.asyncio
    async def test_no_target_hosts_fails(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        result = await check.run({"target_hosts": []})
        assert result.success is False

    @pytest.mark.asyncio
    async def test_empty_context_fails(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        result = await check.run({})
        assert result.success is False

    @pytest.mark.asyncio
    async def test_resolves_aaaa_for_each_host(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.side_effect = [
                ["2001:db8::1"],  # www
                [],  # api — no IPv6
                ["2001:db8::3"],  # cdn
            ]
            context = {
                "target_hosts": ["www.example.com", "api.example.com", "cdn.example.com"],
                "dns_records": {
                    "www.example.com": "1.2.3.4",
                    "api.example.com": "5.6.7.8",
                    "cdn.example.com": "9.10.11.12",
                },
            }
            result = await check.run(context)
            assert result.success is True
            assert mock_resolve.call_count == 3

    @pytest.mark.asyncio
    async def test_outputs_ipv6_data_structure(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = ["2001:db8::1"]
            context = {
                "target_hosts": ["www.example.com"],
                "dns_records": {"www.example.com": "1.2.3.4"},
            }
            result = await check.run(context)
            data = result.outputs["ipv6_data"]
            assert "www.example.com" in data
            entry = data["www.example.com"]
            assert "ipv6_addresses" in entry
            assert "has_ipv4" in entry
            assert "ipv6_only" in entry
            assert "ula_detected" in entry

    @pytest.mark.asyncio
    async def test_no_ipv6_hosts_empty_output(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = []
            context = {
                "target_hosts": ["www.example.com"],
                "dns_records": {"www.example.com": "1.2.3.4"},
            }
            result = await check.run(context)
            assert result.outputs["ipv6_data"] == {}
            assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_dual_stack_detection(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = ["2001:db8::1"]
            context = {
                "target_hosts": ["www.example.com"],
                "dns_records": {"www.example.com": "1.2.3.4"},
            }
            result = await check.run(context)
            entry = result.outputs["ipv6_data"]["www.example.com"]
            assert entry["has_ipv4"] is True
            assert entry["ipv6_only"] is False


class TestIPv6DiscoveryFindings:
    """Test finding generation from IPv6 discovery."""

    @pytest.mark.asyncio
    async def test_ipv6_info_finding(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = ["2001:db8::1"]
            context = {
                "target_hosts": ["www.example.com"],
                "dns_records": {"www.example.com": "1.2.3.4"},
            }
            result = await check.run(context)
            info_findings = [f for f in result.findings if f.severity == "info"]
            assert any("ipv6" in f.title.lower() for f in info_findings)

    @pytest.mark.asyncio
    async def test_ipv6_only_medium_finding(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = ["2001:db8::1"]
            context = {
                "target_hosts": ["v6only.example.com"],
                "dns_records": {},  # No IPv4 record
            }
            result = await check.run(context)
            medium_findings = [f for f in result.findings if f.severity == "medium"]
            assert any(
                "ipv6" in f.title.lower() and "ipv4" in f.title.lower() for f in medium_findings
            )

    @pytest.mark.asyncio
    async def test_ula_finding(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = ["fd00::42"]
            context = {
                "target_hosts": ["internal.example.com"],
                "dns_records": {"internal.example.com": "10.0.0.1"},
            }
            result = await check.run(context)
            low_findings = [f for f in result.findings if f.severity == "low"]
            assert any(
                "ula" in f.title.lower() or "unique local" in f.title.lower() for f in low_findings
            )

    @pytest.mark.asyncio
    async def test_multiple_ipv6_addresses(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = ["2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4"]
            context = {
                "target_hosts": ["cdn.example.com"],
                "dns_records": {"cdn.example.com": "1.2.3.4"},
            }
            result = await check.run(context)
            entry = result.outputs["ipv6_data"]["cdn.example.com"]
            assert len(entry["ipv6_addresses"]) == 4
            # Info finding should mention count
            info = [f for f in result.findings if f.severity == "info"]
            assert any("4" in f.description for f in info)


class TestIPv6ResolveAAAA:
    """Test AAAA resolution methods."""

    def test_sync_resolve_with_dnspython(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with (
            patch("app.checks.network.ipv6_discovery.HAS_DNSPYTHON", True),
            patch("app.checks.network.ipv6_discovery.dns") as mock_dns,
        ):
            mock_answers = [MagicMock(__str__=lambda self: "2001:db8::1")]
            mock_dns.resolver.Resolver.return_value.resolve.return_value = mock_answers
            result = check._sync_resolve_aaaa("www.example.com")
            assert "2001:db8::1" in result

    def test_sync_resolve_fallback_socket(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with (
            patch("app.checks.network.ipv6_discovery.HAS_DNSPYTHON", False),
            patch("socket.getaddrinfo") as mock_getaddr,
        ):
            mock_getaddr.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2001:db8::1", 0, 0, 0)),
            ]
            result = check._sync_resolve_aaaa("www.example.com")
            assert "2001:db8::1" in result

    def test_sync_resolve_nxdomain(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with (
            patch("app.checks.network.ipv6_discovery.HAS_DNSPYTHON", True),
            patch("app.checks.network.ipv6_discovery.dns") as mock_dns,
        ):
            mock_dns.resolver.NXDOMAIN = type("NXDOMAIN", (Exception,), {})
            mock_dns.resolver.NoAnswer = type("NoAnswer", (Exception,), {})
            mock_dns.resolver.NoNameservers = type("NoNameservers", (Exception,), {})
            mock_dns.exception.Timeout = type("Timeout", (Exception,), {})
            mock_dns.exception.DNSException = type("DNSException", (Exception,), {})
            mock_dns.resolver.Resolver.return_value.resolve.side_effect = (
                mock_dns.resolver.NXDOMAIN()
            )
            result = check._sync_resolve_aaaa("nonexistent.example.com")
            assert result == []

    def test_sync_resolve_deduplicates(self):
        from app.checks.network.ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with (
            patch("app.checks.network.ipv6_discovery.HAS_DNSPYTHON", True),
            patch("app.checks.network.ipv6_discovery.dns") as mock_dns,
        ):
            # Return duplicate addresses
            mock_r1 = MagicMock()
            mock_r1.__str__ = lambda self: "2001:db8::1"
            mock_r2 = MagicMock()
            mock_r2.__str__ = lambda self: "2001:db8::1"
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_r1, mock_r2]
            result = check._sync_resolve_aaaa("www.example.com")
            assert len(result) == 1


class TestIPv6CheckResolver:
    """Test that IPv6DiscoveryCheck is registered in check_resolver."""

    def test_ipv6_discovery_registered(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "ipv6_discovery" in names

    def test_ipv6_discovery_in_network_suite(self):
        from app.check_resolver import infer_suite

        assert infer_suite("ipv6_discovery") == "network"
