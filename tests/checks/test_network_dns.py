"""
Tests for Phase 7a network checks: WildcardDnsCheck, DnsRecordCheck, GeoIpCheck

All DNS/network calls are mocked to avoid real traffic.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.checks.network.dns_records import HAS_DNSPYTHON, DnsRecordCheck
from app.checks.network.geoip import HOSTING_ASNS, RESIDENTIAL_ASNS, GeoIpCheck
from app.checks.network.wildcard_dns import WildcardDnsCheck, _random_subdomain

# ═══════════════════════════════════════════════════════════════════════════════
# WildcardDnsCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestWildcardDnsCheckInit:
    """Tests for WildcardDnsCheck initialization."""

    def test_metadata(self):
        check = WildcardDnsCheck()
        assert check.name == "wildcard_dns"
        assert check.conditions == []
        assert "wildcard_dns" in check.produces
        assert len(check.references) > 0

    def test_random_subdomain_generation(self):
        s1 = _random_subdomain()
        s2 = _random_subdomain()
        assert len(s1) == 12
        assert s1 != s2  # Extremely unlikely to collide


class TestWildcardDnsCheckRun:
    """Tests for WildcardDnsCheck run behavior."""

    async def test_no_base_domain_fails(self):
        check = WildcardDnsCheck()
        result = await check.run({})
        assert result.success is False
        assert any("base_domain" in e for e in result.errors)

    @patch("app.checks.network.wildcard_dns.WildcardDnsCheck._resolve")
    async def test_no_wildcard(self, mock_resolve):
        """Random subdomains don't resolve -> no wildcard detected."""
        mock_resolve.return_value = None
        check = WildcardDnsCheck()
        result = await check.run({"base_domain": "example.com"})

        assert result.success is True
        assert result.outputs["wildcard_dns"]["detected"] is False
        assert result.outputs["wildcard_dns"]["ip"] is None
        assert len(result.findings) == 0

    @patch("app.checks.network.wildcard_dns.WildcardDnsCheck._resolve")
    async def test_wildcard_detected_single_ip(self, mock_resolve):
        """All random subdomains resolve to same IP -> wildcard."""
        mock_resolve.return_value = "1.2.3.4"
        check = WildcardDnsCheck()
        result = await check.run({"base_domain": "example.com"})

        assert result.success is True
        wc = result.outputs["wildcard_dns"]
        assert wc["detected"] is True
        assert wc["ip"] == "1.2.3.4"
        assert wc["probes_resolved"] == 3
        assert len(result.findings) == 1
        assert "Wildcard DNS detected" in result.findings[0].title

    @patch("app.checks.network.wildcard_dns.WildcardDnsCheck._resolve")
    async def test_wildcard_detected_multiple_ips(self, mock_resolve):
        """Random subdomains resolve to different IPs -> possible wildcard with round-robin."""
        mock_resolve.side_effect = ["1.2.3.4", "5.6.7.8", "1.2.3.4"]
        check = WildcardDnsCheck()
        result = await check.run({"base_domain": "example.com"})

        wc = result.outputs["wildcard_dns"]
        assert wc["detected"] is True
        assert wc["ip"] is None  # Not a single consistent IP
        assert len(wc["resolved_ips"]) == 2
        assert (
            "round-robin" in result.findings[0].description.lower()
            or "geo-DNS" in result.findings[0].description
        )

    @patch("app.checks.network.wildcard_dns.WildcardDnsCheck._resolve")
    async def test_partial_resolution(self, mock_resolve):
        """Only some random subdomains resolve -> still flagged."""
        mock_resolve.side_effect = ["1.2.3.4", None, None]
        check = WildcardDnsCheck()
        result = await check.run({"base_domain": "example.com"})

        wc = result.outputs["wildcard_dns"]
        assert wc["detected"] is True
        assert wc["probes_resolved"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# DnsRecordCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDnsRecordCheckInit:
    """Tests for DnsRecordCheck initialization."""

    def test_metadata(self):
        check = DnsRecordCheck()
        assert check.name == "dns_records"
        assert check.conditions == []
        assert "dns_extra_records" in check.produces
        assert "dns_extra_hosts" in check.produces

    def test_record_types(self):
        check = DnsRecordCheck()
        assert "MX" in check.RECORD_TYPES
        assert "NS" in check.RECORD_TYPES
        assert "TXT" in check.RECORD_TYPES
        assert "AAAA" in check.RECORD_TYPES


class TestDnsRecordCheckRun:
    """Tests for DnsRecordCheck run behavior."""

    async def test_no_base_domain_fails(self):
        check = DnsRecordCheck()
        result = await check.run({})
        assert result.success is False
        assert any("base_domain" in e for e in result.errors)

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_mx_record_extraction(self, MockResolver):
        """MX records are parsed and hosts extracted."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        # MX query returns a record
        mx_rdata = MagicMock()
        mx_rdata.to_text.return_value = "10 mail.example.com."
        mock_resolver.resolve.side_effect = _make_resolve_side_effect(
            {
                "MX": [mx_rdata],
            }
        )

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert result.success is True
        assert "mail.example.com" in result.outputs["dns_extra_hosts"]
        mx_findings = [f for f in result.findings if "MX record" in f.title]
        assert len(mx_findings) == 1
        assert "mail.example.com" in mx_findings[0].title

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_txt_spf_google(self, MockResolver):
        """SPF record with Google include is flagged."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        txt_rdata = MagicMock()
        txt_rdata.to_text.return_value = '"v=spf1 include:_spf.google.com ~all"'
        mock_resolver.resolve.side_effect = _make_resolve_side_effect(
            {
                "TXT": [txt_rdata],
            }
        )

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        spf_findings = [f for f in result.findings if "SPF" in f.title]
        assert len(spf_findings) == 1
        assert "Google Workspace" in spf_findings[0].title
        assert spf_findings[0].severity == "low"

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_txt_verification_token(self, MockResolver):
        """Verification tokens in TXT records are flagged."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        txt_rdata = MagicMock()
        txt_rdata.to_text.return_value = '"google-site-verification=abc123def456"'
        mock_resolver.resolve.side_effect = _make_resolve_side_effect(
            {
                "TXT": [txt_rdata],
            }
        )

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        verify_findings = [f for f in result.findings if "verification" in f.title.lower()]
        assert len(verify_findings) == 1
        assert verify_findings[0].severity == "low"

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_ns_record(self, MockResolver):
        """NS records generate info findings."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        ns_rdata = MagicMock()
        ns_rdata.to_text.return_value = "ns1.cloudflare.com."
        mock_resolver.resolve.side_effect = _make_resolve_side_effect(
            {
                "NS": [ns_rdata],
            }
        )

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        ns_findings = [f for f in result.findings if "NS record" in f.title]
        assert len(ns_findings) == 1
        assert ns_findings[0].severity == "info"

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_cname_extracted_as_extra_host(self, MockResolver):
        """CNAME targets are added to extra_hosts."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        cname_rdata = MagicMock()
        cname_rdata.to_text.return_value = "cdn.cloudfront.net."
        mock_resolver.resolve.side_effect = _make_resolve_side_effect(
            {
                "CNAME": [cname_rdata],
            }
        )

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert "cdn.cloudfront.net" in result.outputs["dns_extra_hosts"]

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_aaaa_record(self, MockResolver):
        """AAAA records generate IPv6 findings."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        aaaa_rdata = MagicMock()
        aaaa_rdata.to_text.return_value = "2001:db8::1"
        mock_resolver.resolve.side_effect = _make_resolve_side_effect(
            {
                "AAAA": [aaaa_rdata],
            }
        )

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        ipv6_findings = [f for f in result.findings if "IPv6" in f.title]
        assert len(ipv6_findings) == 1

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_soa_record(self, MockResolver):
        """SOA records generate info findings."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        soa_rdata = MagicMock()
        soa_rdata.to_text.return_value = (
            "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"
        )
        mock_resolver.resolve.side_effect = _make_resolve_side_effect(
            {
                "SOA": [soa_rdata],
            }
        )

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        soa_findings = [f for f in result.findings if "SOA" in f.title]
        assert len(soa_findings) == 1

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_nxdomain(self, MockResolver):
        """NXDOMAIN causes early failure."""
        import dns.resolver as _dns_resolver

        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        mock_resolver.resolve.side_effect = _dns_resolver.NXDOMAIN()

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "nonexistent.example.com"})

        assert result.success is False
        assert any("NXDOMAIN" in e for e in result.errors)

    @patch("app.checks.network.dns_records.HAS_DNSPYTHON", False)
    async def test_missing_dnspython(self):
        """Check fails gracefully without dnspython."""
        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})
        assert result.success is False
        assert any("dnspython" in e for e in result.errors)

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_multiple_record_types(self, MockResolver):
        """Multiple record types are all processed."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        mx_rdata = MagicMock()
        mx_rdata.to_text.return_value = "10 mail.example.com."
        ns_rdata = MagicMock()
        ns_rdata.to_text.return_value = "ns1.example.com."

        mock_resolver.resolve.side_effect = _make_resolve_side_effect(
            {
                "MX": [mx_rdata],
                "NS": [ns_rdata],
            }
        )

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert "MX" in result.outputs["dns_extra_records"]
        assert "NS" in result.outputs["dns_extra_records"]


# ═══════════════════════════════════════════════════════════════════════════════
# GeoIpCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestGeoIpCheckInit:
    """Tests for GeoIpCheck initialization."""

    def test_metadata(self):
        check = GeoIpCheck()
        assert check.name == "geoip"
        assert "geoip_data" in check.produces
        assert len(check.conditions) == 1  # depends on dns_records

    def test_hosting_asn_list(self):
        """Hosting ASN list contains major providers."""
        assert 16509 in HOSTING_ASNS  # AWS
        assert 13335 in HOSTING_ASNS  # Cloudflare
        assert 15169 in HOSTING_ASNS  # Google Cloud

    def test_residential_asn_list(self):
        """Residential ASN list contains major ISPs."""
        assert 7922 in RESIDENTIAL_ASNS  # Comcast
        assert 7018 in RESIDENTIAL_ASNS  # AT&T


class TestGeoIpCheckRun:
    """Tests for GeoIpCheck run behavior."""

    @patch("app.checks.network.geoip._find_db_file")
    async def test_no_dns_records(self, mock_find):
        """Check returns early if no dns_records in context."""
        mock_find.side_effect = lambda f: f"/fake/{f}"
        check = GeoIpCheck()
        result = await check.run({"dns_records": {}})
        assert any("dns_records" in e for e in result.errors)

    @patch("app.checks.network.geoip.HAS_GEOIP2", False)
    async def test_missing_geoip2(self):
        """Check fails gracefully without geoip2."""
        check = GeoIpCheck()
        result = await check.run({"dns_records": {"example.com": "1.2.3.4"}})
        assert result.success is False
        assert any("geoip2" in e for e in result.errors)

    @patch("app.checks.network.geoip._find_db_file")
    async def test_missing_db_files(self, mock_find):
        """Check fails gracefully without database files."""
        mock_find.return_value = None
        check = GeoIpCheck()
        result = await check.run({"dns_records": {"example.com": "1.2.3.4"}})
        assert result.success is False
        assert any("GeoLite2" in e for e in result.errors)

    @patch("app.checks.network.geoip._find_db_file")
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_hosting_ip_classification(self, MockReader, mock_find):
        """AWS IP is classified as hosting."""
        mock_find.side_effect = lambda f: f"/fake/{f}"

        city_reader = MagicMock()
        asn_reader = MagicMock()

        # City response
        city_resp = MagicMock()
        city_resp.country.name = "United States"
        city_resp.country.iso_code = "US"
        city_resp.subdivisions.most_specific.name = "Virginia"
        city_resp.subdivisions.__bool__ = lambda self: True
        city_resp.city.name = "Ashburn"
        city_resp.location.latitude = 39.0438
        city_resp.location.longitude = -77.4874
        city_reader.city.return_value = city_resp

        # ASN response — AWS
        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 16509
        asn_resp.autonomous_system_organization = "Amazon.com, Inc."
        asn_reader.asn.return_value = asn_resp

        MockReader.side_effect = [city_reader, asn_reader]

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {"api.example.com": "54.239.28.85"},
            }
        )

        assert result.success is True
        data = result.outputs["geoip_data"]["54.239.28.85"]
        assert data["classification"] == "hosting"
        assert data["provider"] == "Amazon AWS"
        assert data["country_code"] == "US"

        # Should have one info finding (geo) and no medium findings (not residential)
        severities = [f.severity for f in result.findings]
        assert "info" in severities
        assert "medium" not in severities

    @patch("app.checks.network.geoip._find_db_file")
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_residential_ip_flagged(self, MockReader, mock_find):
        """Residential ISP IP generates a medium severity finding."""
        mock_find.side_effect = lambda f: f"/fake/{f}"

        city_reader = MagicMock()
        asn_reader = MagicMock()

        city_resp = MagicMock()
        city_resp.country.name = "United States"
        city_resp.country.iso_code = "US"
        city_resp.subdivisions.most_specific.name = "Pennsylvania"
        city_resp.subdivisions.__bool__ = lambda self: True
        city_resp.city.name = "Philadelphia"
        city_resp.location.latitude = 39.95
        city_resp.location.longitude = -75.16
        city_reader.city.return_value = city_resp

        # ASN response — Comcast (residential)
        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 7922
        asn_resp.autonomous_system_organization = "Comcast Cable Communications"
        asn_reader.asn.return_value = asn_resp

        MockReader.side_effect = [city_reader, asn_reader]

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {"dev.example.com": "73.100.50.25"},
            }
        )

        data = result.outputs["geoip_data"]["73.100.50.25"]
        assert data["classification"] == "residential"

        residential_findings = [f for f in result.findings if f.severity == "medium"]
        assert len(residential_findings) == 1
        assert "Residential IP" in residential_findings[0].title

    @patch("app.checks.network.geoip._find_db_file")
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_unknown_asn_flagged_low(self, MockReader, mock_find):
        """Unknown ASN (not in hosting or residential list) generates low finding."""
        mock_find.side_effect = lambda f: f"/fake/{f}"

        city_reader = MagicMock()
        asn_reader = MagicMock()

        city_resp = MagicMock()
        city_resp.country.name = "Germany"
        city_resp.country.iso_code = "DE"
        city_resp.subdivisions.most_specific.name = "Bavaria"
        city_resp.subdivisions.__bool__ = lambda self: True
        city_resp.city.name = "Munich"
        city_resp.location.latitude = 48.1
        city_resp.location.longitude = 11.5
        city_reader.city.return_value = city_resp

        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 99999
        asn_resp.autonomous_system_organization = "Obscure Hosting GmbH"
        asn_reader.asn.return_value = asn_resp

        MockReader.side_effect = [city_reader, asn_reader]

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {"ml.example.com": "185.1.2.3"},
            }
        )

        data = result.outputs["geoip_data"]["185.1.2.3"]
        assert data["classification"] == "other"

        low_findings = [f for f in result.findings if f.severity == "low"]
        assert len(low_findings) == 1
        assert "Non-standard" in low_findings[0].title

    @patch("app.checks.network.geoip._find_db_file")
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_multiple_hosts_same_ip(self, MockReader, mock_find):
        """Multiple hostnames resolving to the same IP are grouped."""
        mock_find.side_effect = lambda f: f"/fake/{f}"

        city_reader = MagicMock()
        asn_reader = MagicMock()

        city_resp = MagicMock()
        city_resp.country.name = "United States"
        city_resp.country.iso_code = "US"
        city_resp.subdivisions.most_specific.name = "Virginia"
        city_resp.subdivisions.__bool__ = lambda self: True
        city_resp.city.name = "Ashburn"
        city_resp.location.latitude = 39.0
        city_resp.location.longitude = -77.4
        city_reader.city.return_value = city_resp

        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 16509
        asn_resp.autonomous_system_organization = "Amazon.com, Inc."
        asn_reader.asn.return_value = asn_resp

        MockReader.side_effect = [city_reader, asn_reader]

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {
                    "api.example.com": "54.1.2.3",
                    "www.example.com": "54.1.2.3",
                },
            }
        )

        # Should only look up the IP once (deduplicated)
        assert result.targets_checked == 1
        assert "54.1.2.3" in result.outputs["geoip_data"]

    @patch("app.checks.network.geoip._find_db_file")
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_asn_only_db(self, MockReader, mock_find):
        """Check works with only ASN database (no city)."""
        mock_find.side_effect = lambda f: f"/fake/{f}" if "ASN" in f else None

        asn_reader = MagicMock()
        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 13335
        asn_resp.autonomous_system_organization = "Cloudflare, Inc."
        asn_reader.asn.return_value = asn_resp

        MockReader.return_value = asn_reader

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {"cdn.example.com": "104.16.1.1"},
            }
        )

        assert result.success is True
        data = result.outputs["geoip_data"]["104.16.1.1"]
        assert data["classification"] == "hosting"
        assert data["provider"] == "Cloudflare"
        assert data["country"] is None  # No city DB


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: Check Resolver Registration
# ═══════════════════════════════════════════════════════════════════════════════


class TestPhase7aRegistration:
    """Verify Phase 7a checks are properly registered."""

    def test_checks_in_resolver(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "wildcard_dns" in names
        assert "dns_records" in names
        assert "geoip" in names

    def test_check_order(self):
        """Phase 7a checks run before port_scan."""
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        wc_idx = names.index("wildcard_dns")
        dr_idx = names.index("dns_records")
        geo_idx = names.index("geoip")
        ps_idx = names.index("port_scan")

        # wildcard_dns and dns_records before geoip, geoip before port_scan
        assert wc_idx < geo_idx
        assert dr_idx < geo_idx
        assert geo_idx < ps_idx

    def test_suite_inference(self):
        from app.check_resolver import infer_suite

        assert infer_suite("wildcard_dns") == "network"
        assert infer_suite("dns_records") == "network"
        assert infer_suite("geoip") == "network"


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _make_resolve_side_effect(records: dict):
    """
    Create a side_effect function for mock resolver.resolve().

    Args:
        records: dict of record_type -> list of mock rdata objects

    Returns:
        A function that returns the matching records or raises NoAnswer.
    """
    import dns.resolver as _dns_resolver

    def _resolve(domain, rtype):
        if rtype in records:
            return records[rtype]
        raise _dns_resolver.NoAnswer()

    return _resolve
