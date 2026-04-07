"""Tests for WhoisLookupCheck: WHOIS domain registration, parsing, ASN/RDAP lookup, and observations."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest


class TestWhoisLookupCheckInit:
    """Test WhoisLookupCheck metadata and initialization."""

    def test_check_metadata(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        assert check.name == "whois_lookup"
        assert "whois" in check.description.lower() or "asn" in check.description.lower()

    def test_conditions(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "dns_records"
        assert check.conditions[0].operator == "truthy"

    def test_produces(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        assert "whois_data" in check.produces

    def test_references(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        assert len(check.references) > 0

    def test_conservative_rate_limit(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        # WHOIS servers rate-limit aggressively
        assert check.requests_per_second <= 5.0

    def test_whois_servers_defined(self):
        from app.checks.network.whois_lookup import WHOIS_SERVERS

        assert "com" in WHOIS_SERVERS
        assert "net" in WHOIS_SERVERS
        assert "org" in WHOIS_SERVERS
        assert "io" in WHOIS_SERVERS


class TestWhoisLookupCheckRun:
    """Test WhoisLookupCheck runtime behavior."""

    @pytest.mark.asyncio
    async def test_no_dns_records_fails(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        result = await check.run({"dns_records": {}})
        assert result.success is False

    @pytest.mark.asyncio
    async def test_empty_dns_records_fails(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        result = await check.run({})
        assert result.success is False

    @pytest.mark.asyncio
    async def test_domain_whois_called_with_base_domain(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        with (
            patch.object(check, "_domain_whois", new_callable=AsyncMock) as mock_whois,
            patch.object(check, "_asn_lookup", new_callable=AsyncMock) as mock_asn,
        ):
            mock_whois.return_value = {
                "domain": "example.com",
                "registrar": "Test Registrar",
                "created": "2020-01-01",
                "expires": "2025-01-01",
                "nameservers": ["ns1.example.com"],
                "status": [],
                "redacted": False,
            }
            mock_asn.return_value = None

            context = {
                "dns_records": {"www.example.com": "1.2.3.4"},
                "base_domain": "example.com",
            }
            result = await check.run(context)
            assert result.success is True
            assert "whois_data" in result.outputs
            assert result.outputs["whois_data"]["domain"]["registrar"] == "Test Registrar"
            mock_whois.assert_called_once_with("example.com")

    @pytest.mark.asyncio
    async def test_no_base_domain_skips_domain_whois(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        with (
            patch.object(check, "_domain_whois", new_callable=AsyncMock) as mock_whois,
            patch.object(check, "_asn_lookup", new_callable=AsyncMock) as mock_asn,
        ):
            mock_asn.return_value = None
            context = {"dns_records": {"www.example.com": "1.2.3.4"}}
            result = await check.run(context)
            assert result.success is True
            mock_whois.assert_not_called()

    @pytest.mark.asyncio
    async def test_asn_lookup_per_unique_ip(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        with (
            patch.object(check, "_domain_whois", new_callable=AsyncMock) as mock_whois,
            patch.object(check, "_asn_lookup", new_callable=AsyncMock) as mock_asn,
        ):
            mock_whois.return_value = None
            mock_asn.return_value = {
                "ip": "1.2.3.4",
                "asn": 16509,
                "asn_description": "Amazon",
                "asn_country": "US",
                "network_name": "AMAZON-AES",
                "network_cidr": "1.2.0.0/16",
            }

            context = {
                "dns_records": {
                    "www.example.com": "1.2.3.4",
                    "api.example.com": "1.2.3.4",  # Same IP
                    "cdn.example.com": "5.6.7.8",  # Different IP
                },
                "base_domain": "example.com",
            }
            result = await check.run(context)
            assert result.success is True
            # Should look up 2 unique IPs, not 3
            assert mock_asn.call_count == 2

    @pytest.mark.asyncio
    async def test_outputs_whois_data_structure(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        with (
            patch.object(check, "_domain_whois", new_callable=AsyncMock) as mock_whois,
            patch.object(check, "_asn_lookup", new_callable=AsyncMock) as mock_asn,
        ):
            mock_whois.return_value = {"domain": "example.com", "registrar": "R"}
            mock_asn.return_value = {"ip": "1.2.3.4", "asn": 16509}

            context = {
                "dns_records": {"www.example.com": "1.2.3.4"},
                "base_domain": "example.com",
            }
            result = await check.run(context)
            data = result.outputs["whois_data"]
            assert "domain" in data
            assert "asn" in data
            assert "1.2.3.4" in data["asn"]


class TestWhoisParseResponse:
    """Test WHOIS response parsing."""

    def test_parse_standard_com_whois(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        raw = (
            "Domain Name: EXAMPLE.COM\r\n"
            "Registrar: Test Registrar, Inc.\r\n"
            "Creation Date: 2019-03-15T00:00:00Z\r\n"
            "Registry Expiry Date: 2025-03-15T00:00:00Z\r\n"
            "Updated Date: 2024-01-01T00:00:00Z\r\n"
            "Name Server: NS1.EXAMPLE.COM\r\n"
            "Name Server: NS2.EXAMPLE.COM\r\n"
            "Domain Status: clientTransferProhibited\r\n"
            "DNSSEC: unsigned\r\n"
        )
        info = check._parse_whois_response(raw, "example.com")
        assert info["registrar"] == "Test Registrar, Inc."
        assert info["created"] == "2019-03-15T00:00:00Z"
        assert info["expires"] == "2025-03-15T00:00:00Z"
        assert "ns1.example.com" in info["nameservers"]
        assert "ns2.example.com" in info["nameservers"]
        assert "clientTransferProhibited" in info["status"]
        assert info["dnssec"] == "unsigned"

    def test_parse_redacted_whois(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        raw = (
            "Domain Name: EXAMPLE.COM\r\n"
            "Registrar: Namecheap\r\n"
            "Registrant Name: REDACTED FOR PRIVACY\r\n"
            "Creation Date: 2020-05-01\r\n"
        )
        info = check._parse_whois_response(raw, "example.com")
        assert info["redacted"] is True
        assert info["registrar"] == "Namecheap"

    def test_parse_empty_response(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        info = check._parse_whois_response("", "example.com")
        assert info["registrar"] is None
        assert info["nameservers"] == []

    def test_parse_comments_skipped(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        raw = "% This is a comment\r\n# Another comment\r\nRegistrar: Actual Registrar\r\n"
        info = check._parse_whois_response(raw, "example.com")
        assert info["registrar"] == "Actual Registrar"


class TestWhoisDomainAgeDays:
    """Test domain age calculation."""

    def test_iso_format(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        days = WhoisLookupCheck._domain_age_days("2020-01-01T00:00:00Z")
        assert days is not None
        assert days > 365

    def test_date_only_format(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        days = WhoisLookupCheck._domain_age_days("2020-01-01")
        assert days is not None
        assert days > 365

    def test_unparseable_returns_none(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        days = WhoisLookupCheck._domain_age_days("not-a-date")
        assert days is None

    def test_recent_date(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        # A date within the last 30 days
        recent = (datetime.now(UTC) - timedelta(days=15)).strftime("%Y-%m-%d")
        days = WhoisLookupCheck._domain_age_days(recent)
        assert days is not None
        assert 10 <= days <= 20


class TestWhoisDomainObservations:
    """Test observation generation from domain WHOIS data."""

    @pytest.mark.asyncio
    async def test_registration_info_observation(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        with (
            patch.object(check, "_domain_whois", new_callable=AsyncMock) as mock_whois,
            patch.object(check, "_asn_lookup", new_callable=AsyncMock) as mock_asn,
        ):
            mock_whois.return_value = {
                "domain": "example.com",
                "registrar": "Cloudflare, Inc.",
                "created": "2019-03-15T00:00:00Z",
                "expires": "2025-03-15T00:00:00Z",
                "nameservers": ["ns1.cloudflare.com"],
                "status": [],
                "redacted": False,
                "raw_length": 500,
                "updated": None,
                "dnssec": None,
            }
            mock_asn.return_value = None

            context = {
                "dns_records": {"www.example.com": "1.2.3.4"},
                "base_domain": "example.com",
            }
            result = await check.run(context)
            info_observations = [f for f in result.observations if f.severity == "info"]
            assert any("registrar" in f.title.lower() for f in info_observations)

    @pytest.mark.asyncio
    async def test_recent_registration_observation(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        recent_date = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with (
            patch.object(check, "_domain_whois", new_callable=AsyncMock) as mock_whois,
            patch.object(check, "_asn_lookup", new_callable=AsyncMock) as mock_asn,
        ):
            mock_whois.return_value = {
                "domain": "newsite.com",
                "registrar": "GoDaddy",
                "created": recent_date,
                "expires": "2027-01-01T00:00:00Z",
                "nameservers": [],
                "status": [],
                "redacted": False,
                "raw_length": 300,
                "updated": None,
                "dnssec": None,
            }
            mock_asn.return_value = None

            context = {
                "dns_records": {"newsite.com": "1.2.3.4"},
                "base_domain": "newsite.com",
            }
            result = await check.run(context)
            low_observations = [f for f in result.observations if f.severity == "low"]
            assert any(
                "registered within" in f.title.lower() or "90 days" in f.title for f in low_observations
            )

    @pytest.mark.asyncio
    async def test_redacted_observation(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        with (
            patch.object(check, "_domain_whois", new_callable=AsyncMock) as mock_whois,
            patch.object(check, "_asn_lookup", new_callable=AsyncMock) as mock_asn,
        ):
            mock_whois.return_value = {
                "domain": "example.com",
                "registrar": "Namecheap",
                "created": "2020-01-01",
                "expires": "2025-01-01",
                "nameservers": [],
                "status": [],
                "redacted": True,
                "raw_length": 400,
                "updated": None,
                "dnssec": None,
            }
            mock_asn.return_value = None

            context = {
                "dns_records": {"example.com": "1.2.3.4"},
                "base_domain": "example.com",
            }
            result = await check.run(context)
            assert any("redacted" in f.title.lower() for f in result.observations)


class TestWhoisAsnObservations:
    """Test observation generation from ASN/RDAP data."""

    @pytest.mark.asyncio
    async def test_asn_info_observation(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        with (
            patch.object(check, "_domain_whois", new_callable=AsyncMock) as mock_whois,
            patch.object(check, "_asn_lookup", new_callable=AsyncMock) as mock_asn,
        ):
            mock_whois.return_value = None
            mock_asn.return_value = {
                "ip": "1.2.3.4",
                "asn": 16509,
                "asn_description": "AMAZON-02",
                "asn_country": "US",
                "network_name": "AMAZON-AES",
                "network_cidr": "1.2.0.0/16",
                "asn_registry": "arin",
                "network_country": "US",
            }

            context = {
                "dns_records": {"api.example.com": "1.2.3.4"},
                "base_domain": "example.com",
            }
            result = await check.run(context)
            info_observations = [f for f in result.observations if f.severity == "info"]
            assert any("AS16509" in f.title for f in info_observations)

    @pytest.mark.asyncio
    async def test_private_ip_observation(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        with (
            patch.object(check, "_domain_whois", new_callable=AsyncMock) as mock_whois,
            patch.object(check, "_asn_lookup", new_callable=AsyncMock) as mock_asn,
        ):
            mock_whois.return_value = None
            mock_asn.return_value = {"ip": "10.0.0.1", "asn": None, "private": True}

            context = {
                "dns_records": {"internal.example.com": "10.0.0.1"},
                "base_domain": "example.com",
            }
            result = await check.run(context)
            assert any("private" in f.title.lower() for f in result.observations)

    @pytest.mark.asyncio
    async def test_no_ipwhois_reports_error(self):
        from app.checks.network.whois_lookup import WhoisLookupCheck

        check = WhoisLookupCheck()
        with (
            patch.object(check, "_domain_whois", new_callable=AsyncMock) as mock_whois,
            patch("app.checks.network.whois_lookup.HAS_IPWHOIS", False),
        ):
            mock_whois.return_value = None
            context = {
                "dns_records": {"www.example.com": "1.2.3.4"},
                "base_domain": "example.com",
            }
            result = await check.run(context)
            assert result.success is True  # Still succeeds (domain whois may work)
            assert any("ipwhois" in e.lower() for e in result.errors)


class TestWhoisCheckResolver:
    """Test that WhoisLookupCheck is registered in check_resolver."""

    def test_whois_lookup_registered(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "whois_lookup" in names

    def test_whois_in_network_suite(self):
        from app.check_resolver import infer_suite

        assert infer_suite("whois_lookup") == "network"

    def test_total_check_count(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        # Was 43 checks (Phase 7c), now +3 = 46
        assert len(checks) >= 46
