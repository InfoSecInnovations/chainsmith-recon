"""Tests for WildcardDnsCheck and DnsRecordCheck."""

from unittest.mock import MagicMock, patch

import pytest

from app.checks.network.dns_records import HAS_DNSPYTHON, DnsRecordCheck
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
# Integration: Check Resolver Registration
# ═══════════════════════════════════════════════════════════════════════════════


class TestDnsRegistration:
    """Verify DNS checks are properly registered."""

    def test_checks_in_resolver(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "wildcard_dns" in names
        assert "dns_records" in names

    def test_suite_inference(self):
        from app.check_resolver import infer_suite

        assert infer_suite("wildcard_dns") == "network"
        assert infer_suite("dns_records") == "network"


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
