"""Tests for DnsEnumerationCheck: DNS enumeration, resolution, and host discovery."""

import socket
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.network.dns_enumeration import DEFAULT_WORDLIST, DnsEnumerationCheck


class TestDnsEnumerationCheckInit:
    """Tests for DnsEnumerationCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = DnsEnumerationCheck()

        assert check.name == "dns_enumeration"
        assert check.base_domain == ""
        assert check.wordlist == DEFAULT_WORDLIST
        assert check.conditions == []  # Entry point

    def test_custom_initialization(self):
        """Check accepts custom configuration."""
        check = DnsEnumerationCheck(
            base_domain="example.com",
            wordlist=["api", "www"],
        )

        assert check.base_domain == "example.com"
        assert check.wordlist == ["api", "www"]

    def test_metadata(self):
        """Check has educational metadata."""
        check = DnsEnumerationCheck()

        assert "target_hosts" in check.produces
        assert "dns_records" in check.produces
        assert len(check.references) > 0
        assert len(check.techniques) > 0


class TestDnsEnumerationCheckRun:
    """Tests for DnsEnumerationCheck run behavior."""

    async def test_run_no_base_domain_fails(self):
        """Run fails without base_domain."""
        check = DnsEnumerationCheck()
        result = await check.run({})

        assert result.success is False
        assert any("No base_domain" in e for e in result.errors)

    async def test_run_uses_context_base_domain(self):
        """Run uses base_domain from context."""
        check = DnsEnumerationCheck()

        with patch.object(check, "_resolve_host", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = None  # All lookups fail

            await check.run({"base_domain": "example.com"})

            # Should have attempted resolution
            assert mock_resolve.called
            # Check that candidates were formed correctly
            call_args = [call[0][0] for call in mock_resolve.call_args_list]
            assert any("example.com" in arg for arg in call_args)

    async def test_run_uses_constructor_base_domain(self):
        """Run uses base_domain from constructor."""
        check = DnsEnumerationCheck(base_domain="constructor.com", wordlist=["www"])

        with patch.object(check, "_resolve_host", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = None

            await check.run({})

            call_args = [call[0][0] for call in mock_resolve.call_args_list]
            assert "www.constructor.com" in call_args

    async def test_run_resolves_hosts(self):
        """Run resolves hosts and outputs target_hosts and dns_records."""
        check = DnsEnumerationCheck(
            base_domain="example.com",
            wordlist=["www", "api"],
        )

        async def mock_resolve(hostname):
            if hostname == "www.example.com":
                return "192.168.1.1"
            elif hostname == "api.example.com":
                return "192.168.1.2"
            return None

        with patch.object(check, "_resolve_host", side_effect=mock_resolve):
            result = await check.run({})

        assert result.success is True
        assert len(result.findings) == 2

        # DNS outputs hostnames, not services
        assert "www.example.com" in result.outputs["target_hosts"]
        assert "api.example.com" in result.outputs["target_hosts"]
        assert result.outputs["dns_records"]["www.example.com"] == "192.168.1.1"
        assert result.outputs["dns_records"]["api.example.com"] == "192.168.1.2"

    async def test_run_handles_resolution_failures(self):
        """Run continues when some hosts fail to resolve."""
        check = DnsEnumerationCheck(
            base_domain="example.com",
            wordlist=["www", "nonexistent", "api"],
        )

        async def mock_resolve(hostname):
            if "nonexistent" in hostname:
                raise socket.gaierror("Name resolution failed")
            if hostname == "www.example.com":
                return "192.168.1.1"
            return None

        with patch.object(check, "_resolve_host", side_effect=mock_resolve):
            result = await check.run({})

        assert result.success is True
        assert len(result.outputs["target_hosts"]) == 1
        assert "www.example.com" in result.outputs["target_hosts"]

    async def test_run_sets_outputs(self):
        """Run sets target_hosts and dns_records in outputs."""
        check = DnsEnumerationCheck(
            base_domain="example.com",
            wordlist=["www"],
        )

        with patch.object(check, "_resolve_host", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = "192.168.1.1"

            result = await check.run({})

        assert "target_hosts" in result.outputs
        assert "dns_records" in result.outputs
        assert "www.example.com" in result.outputs["target_hosts"]
        assert result.outputs["dns_records"]["www.example.com"] == "192.168.1.1"

    async def test_run_creates_findings(self):
        """Run creates findings for discovered hosts."""
        check = DnsEnumerationCheck(
            base_domain="example.com",
            wordlist=["www"],
        )

        with patch.object(check, "_resolve_host", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = "192.168.1.1"

            result = await check.run({})

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert "www.example.com" in finding.title
        assert finding.severity == "info"
        assert finding.check_name == "dns_enumeration"
        assert finding.target is None  # DNS findings have no Service
        assert finding.target_url is None


class TestDnsEnumerationResolveHost:
    """Tests for _resolve_host method."""

    async def test_resolve_host_success(self):
        """Successful resolution returns IP address."""
        check = DnsEnumerationCheck()

        # Mock socket.getaddrinfo
        mock_result = [(socket.AF_INET, None, None, None, ("192.168.1.1", 0))]

        with patch("socket.getaddrinfo", return_value=mock_result):
            result = await check._resolve_host("example.com")

        assert result == "192.168.1.1"

    async def test_resolve_host_failure(self):
        """Failed resolution returns None."""
        check = DnsEnumerationCheck()

        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Not found")):
            result = await check._resolve_host("nonexistent.example.com")

        assert result is None
