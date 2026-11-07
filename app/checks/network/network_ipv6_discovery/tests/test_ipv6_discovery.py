"""Tests for network_ipv6_discovery."""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def aaaa(*addresses: str):
    """One recorded AAAA exchange, the way `_resolve_aaaa` now hands it back.

    57.4 wave 2: the resolver's answer lives on the exchange's `response_body`,
    so the probe and `grade()` read the same bytes. Mocks return one of these
    instead of a bare address list.
    """
    from app.grading import exchange_from_payload

    return exchange_from_payload(
        "dns",
        "host",
        check_name="network_ipv6_discovery",
        request_body="AAAA",
        response_body=", ".join(addresses),
    )


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


class TestIPv6DiscoveryCheckInit:
    """Test IPv6DiscoveryCheck metadata and initialization."""

    def test_check_metadata(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        assert check.name == "network_ipv6_discovery"
        assert "ipv6" in check.description.lower()

    def test_conditions(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "target_hosts"
        assert check.conditions[0].operator == "truthy"

    def test_produces(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        assert "ipv6_data" in check.produces

    def test_references(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        assert len(check.references) > 0

    def test_ula_prefix_defined(self):
        from app.checks.network.network_ipv6_discovery.check import ULA_PREFIX

        assert ULA_PREFIX == "fd"


class TestIPv6DiscoveryCheckRun:
    """Test IPv6DiscoveryCheck runtime behavior."""

    @pytest.mark.asyncio
    async def test_no_target_hosts_fails(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        result = await check.run({"target_hosts": []})
        assert result.success is False
        assert any("target_hosts" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_empty_context_fails(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        result = await check.run({})
        assert result.success is False

    @pytest.mark.asyncio
    async def test_resolves_aaaa_for_each_host(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.side_effect = [
                aaaa("2001:db8::1"),  # www
                aaaa(),  # api - no IPv6
                aaaa("2001:db8::3"),  # cdn
            ]
            context = {
                "target_hosts": ["www.example.com", "api.example.com", "cdn.example.com"],
                "dns_records": {
                    "www.example.com": "1.2.3.4",
                    "api.example.com": "5.6.7.8",
                    "cdn.example.com": "9.10.11.12",
                },
            }
            result = await probe_and_grade(check, context)
            assert mock_resolve.call_count == 3
            # Only hosts WITH IPv6 appear in output
            assert "www.example.com" in result.outputs["ipv6_data"]
            assert "api.example.com" not in result.outputs["ipv6_data"]
            assert "cdn.example.com" in result.outputs["ipv6_data"]

    @pytest.mark.asyncio
    async def test_outputs_ipv6_data_structure(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = aaaa("2001:db8::1")
            context = {
                "target_hosts": ["www.example.com"],
                "dns_records": {"www.example.com": "1.2.3.4"},
            }
            result = await probe_and_grade(check, context)
            data = result.outputs["ipv6_data"]
            assert "www.example.com" in data
            entry = data["www.example.com"]
            assert entry["ipv6_addresses"] == ["2001:db8::1"]
            assert entry["has_ipv4"] is True
            assert entry["ipv6_only"] is False
            assert entry["ula_detected"] is False

    @pytest.mark.asyncio
    async def test_no_ipv6_hosts_empty_output(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = aaaa()
            context = {
                "target_hosts": ["www.example.com"],
                "dns_records": {"www.example.com": "1.2.3.4"},
            }
            result = await probe_and_grade(check, context)
            assert result.outputs["ipv6_data"] == {}
            assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_dual_stack_detection(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = aaaa("2001:db8::1")
            context = {
                "target_hosts": ["www.example.com"],
                "dns_records": {"www.example.com": "1.2.3.4"},
            }
            result = await probe_and_grade(check, context)
            entry = result.outputs["ipv6_data"]["www.example.com"]
            assert entry["has_ipv4"] is True
            assert entry["ipv6_only"] is False


class TestIPv6DiscoveryObservations:
    """Test observation generation from IPv6 discovery."""

    @pytest.mark.asyncio
    async def test_ipv6_info_observation_title_and_evidence(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = aaaa("2001:db8::1")
            context = {
                "target_hosts": ["www.example.com"],
                "dns_records": {"www.example.com": "1.2.3.4"},
            }
            result = await probe_and_grade(check, context)
            info_obs = [f for f in result.observations if f.severity == "info"]
            ipv6_obs = [f for f in info_obs if "ipv6" in f.title.lower()]
            assert len(ipv6_obs) == 1
            assert "www.example.com" in ipv6_obs[0].title
            assert "2001:db8::1" in ipv6_obs[0].evidence

    @pytest.mark.asyncio
    async def test_ipv6_only_medium_observation_title_and_severity(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = aaaa("2001:db8::1")
            context = {
                "target_hosts": ["v6only.example.com"],
                "dns_records": {},  # No IPv4 record
            }
            result = await probe_and_grade(check, context)
            medium_obs = [f for f in result.observations if f.severity == "medium"]
            assert len(medium_obs) == 1
            assert "ipv6" in medium_obs[0].title.lower()
            assert "ipv4" in medium_obs[0].title.lower()
            assert "v6only.example.com" in medium_obs[0].title

    @pytest.mark.asyncio
    async def test_ula_observation_title_and_severity(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = aaaa("fd00::42")
            context = {
                "target_hosts": ["internal.example.com"],
                "dns_records": {"internal.example.com": "10.0.0.1"},
            }
            result = await probe_and_grade(check, context)
            low_obs = [f for f in result.observations if f.severity == "low"]
            ula_obs = [
                f for f in low_obs if "ula" in f.title.lower() or "unique local" in f.title.lower()
            ]
            assert len(ula_obs) == 1
            assert "internal.example.com" in ula_obs[0].title
            assert "fd00::42" in ula_obs[0].evidence

    @pytest.mark.asyncio
    async def test_multiple_ipv6_addresses_count_in_description(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with patch.object(check, "_resolve_aaaa", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = aaaa(
                "2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4"
            )
            context = {
                "target_hosts": ["cdn.example.com"],
                "dns_records": {"cdn.example.com": "1.2.3.4"},
            }
            result = await probe_and_grade(check, context)
            entry = result.outputs["ipv6_data"]["cdn.example.com"]
            assert len(entry["ipv6_addresses"]) == 4
            info = [f for f in result.observations if f.severity == "info"]
            assert any("4" in f.description for f in info)


class TestIPv6ResolveAAAA:
    """Test AAAA resolution methods at the I/O boundary."""

    def test_sync_resolve_with_dnspython(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with (
            patch("app.checks.network.network_ipv6_discovery.check.HAS_DNSPYTHON", True),
            patch("app.checks.network.network_ipv6_discovery.check.dns") as mock_dns,
        ):
            mock_answers = [MagicMock(__str__=lambda self: "2001:db8::1")]
            mock_dns.resolver.Resolver.return_value.resolve.return_value = mock_answers
            result = check._sync_resolve_aaaa("www.example.com")
            assert result == ["2001:db8::1"]
            mock_dns.resolver.Resolver.return_value.resolve.assert_called_once_with(
                "www.example.com", "AAAA"
            )

    def test_sync_resolve_fallback_socket(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with (
            patch("app.checks.network.network_ipv6_discovery.check.HAS_DNSPYTHON", False),
            patch("socket.getaddrinfo") as mock_getaddr,
        ):
            mock_getaddr.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2001:db8::1", 0, 0, 0)),
            ]
            result = check._sync_resolve_aaaa("www.example.com")
            assert result == ["2001:db8::1"]
            mock_getaddr.assert_called_once_with(
                "www.example.com", None, socket.AF_INET6, socket.SOCK_STREAM
            )

    def test_sync_resolve_nxdomain(self):
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with (
            patch("app.checks.network.network_ipv6_discovery.check.HAS_DNSPYTHON", True),
            patch("app.checks.network.network_ipv6_discovery.check.dns") as mock_dns,
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
        from app.checks.network.network_ipv6_discovery import IPv6DiscoveryCheck

        check = IPv6DiscoveryCheck()
        with (
            patch("app.checks.network.network_ipv6_discovery.check.HAS_DNSPYTHON", True),
            patch("app.checks.network.network_ipv6_discovery.check.dns") as mock_dns,
        ):
            # Return duplicate addresses
            mock_r1 = MagicMock()
            mock_r1.__str__ = lambda self: "2001:db8::1"
            mock_r2 = MagicMock()
            mock_r2.__str__ = lambda self: "2001:db8::1"
            mock_dns.resolver.Resolver.return_value.resolve.return_value = [mock_r1, mock_r2]
            result = check._sync_resolve_aaaa("www.example.com")
            assert len(result) == 1
            assert result == ["2001:db8::1"]
