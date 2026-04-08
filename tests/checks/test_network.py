"""Tests for DnsEnumerationCheck: DNS enumeration, resolution, and host discovery."""

import socket
from unittest.mock import patch

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


def _fake_getaddrinfo(mapping):
    """Return a getaddrinfo side_effect that resolves hostnames via *mapping*.

    Keys are hostnames; values are IP strings.  Hostnames absent from the
    mapping raise ``socket.gaierror``.
    """

    def _resolver(hostname, port, family=None):
        if hostname in mapping:
            return [(socket.AF_INET, None, None, None, (mapping[hostname], 0))]
        raise socket.gaierror(f"Name resolution failed: {hostname}")

    return _resolver


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
        check = DnsEnumerationCheck(wordlist=["www"])

        resolver = _fake_getaddrinfo({"www.example.com": "10.0.0.1"})
        with patch("socket.getaddrinfo", side_effect=resolver):
            result = await check.run({"base_domain": "example.com"})

        assert result.success is True
        assert "www.example.com" in result.outputs["target_hosts"]

    async def test_run_uses_constructor_base_domain(self):
        """Run uses base_domain from constructor."""
        check = DnsEnumerationCheck(base_domain="constructor.com", wordlist=["www"])

        resolver = _fake_getaddrinfo({"www.constructor.com": "10.0.0.1"})
        with patch("socket.getaddrinfo", side_effect=resolver):
            result = await check.run({})

        assert "www.constructor.com" in result.outputs["target_hosts"]
        assert result.outputs["dns_records"]["www.constructor.com"] == "10.0.0.1"

    async def test_run_resolves_hosts(self):
        """Run resolves hosts and outputs target_hosts and dns_records."""
        check = DnsEnumerationCheck(
            base_domain="example.com",
            wordlist=["www", "api"],
        )

        resolver = _fake_getaddrinfo(
            {
                "www.example.com": "192.168.1.1",
                "api.example.com": "192.168.1.2",
            }
        )
        with patch("socket.getaddrinfo", side_effect=resolver):
            result = await check.run({})

        assert result.success is True
        assert len(result.observations) == 2

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

        resolver = _fake_getaddrinfo({"www.example.com": "192.168.1.1"})
        with patch("socket.getaddrinfo", side_effect=resolver):
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

        resolver = _fake_getaddrinfo({"www.example.com": "192.168.1.1"})
        with patch("socket.getaddrinfo", side_effect=resolver):
            result = await check.run({})

        assert "target_hosts" in result.outputs
        assert "dns_records" in result.outputs
        assert "www.example.com" in result.outputs["target_hosts"]
        assert result.outputs["dns_records"]["www.example.com"] == "192.168.1.1"

    async def test_run_creates_observations(self):
        """Run creates observations for discovered hosts."""
        check = DnsEnumerationCheck(
            base_domain="example.com",
            wordlist=["www"],
        )

        resolver = _fake_getaddrinfo({"www.example.com": "192.168.1.1"})
        with patch("socket.getaddrinfo", side_effect=resolver):
            result = await check.run({})

        assert len(result.observations) == 1
        observation = result.observations[0]
        assert "www.example.com" in observation.title
        assert observation.severity == "info"
        assert observation.check_name == "dns_enumeration"
        assert observation.target is None  # DNS observations have no Service
        assert observation.target_url is None


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
