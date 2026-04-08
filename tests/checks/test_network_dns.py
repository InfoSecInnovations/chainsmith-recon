"""Tests for WildcardDnsCheck and DnsRecordCheck."""

import socket
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

    @patch("socket.getaddrinfo")
    async def test_no_wildcard(self, mock_getaddrinfo):
        """Random subdomains don't resolve -> no wildcard detected.

        Mocks socket.getaddrinfo (the I/O boundary used by _resolve)
        to raise gaierror, simulating DNS NXDOMAIN for random subdomains.
        """
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        check = WildcardDnsCheck()
        result = await check.run({"base_domain": "example.com"})

        assert result.success is True
        assert result.outputs["wildcard_dns"]["detected"] is False
        assert result.outputs["wildcard_dns"]["ip"] is None
        assert len(result.observations) == 0

    @patch("socket.getaddrinfo")
    async def test_wildcard_detected_single_ip(self, mock_getaddrinfo):
        """All random subdomains resolve to same IP -> wildcard.

        Mocks socket.getaddrinfo to return a consistent IP for every query,
        letting _resolve() run its real logic.
        """
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
        ]
        check = WildcardDnsCheck()
        result = await check.run({"base_domain": "example.com"})

        assert result.success is True
        wc = result.outputs["wildcard_dns"]
        assert wc["detected"] is True
        assert wc["ip"] == "1.2.3.4"
        assert wc["probes_resolved"] == 3
        assert wc["probes_total"] == 3
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Wildcard DNS detected: *.example.com"
        assert obs.severity == "info"
        assert obs.evidence == "*.example.com -> 1.2.3.4"

    @patch("socket.getaddrinfo")
    async def test_wildcard_detected_multiple_ips(self, mock_getaddrinfo):
        """Random subdomains resolve to different IPs -> possible wildcard with round-robin.

        Each call returns a different IP to simulate round-robin DNS.
        """
        ips = iter(["1.2.3.4", "5.6.7.8", "1.2.3.4"])

        def _getaddrinfo(hostname, port, family):
            ip = next(ips)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

        mock_getaddrinfo.side_effect = _getaddrinfo
        check = WildcardDnsCheck()
        result = await check.run({"base_domain": "example.com"})

        wc = result.outputs["wildcard_dns"]
        assert wc["detected"] is True
        assert wc["ip"] is None  # Not a single consistent IP
        assert len(wc["resolved_ips"]) == 2
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Wildcard DNS detected: *.example.com"
        assert obs.severity == "info"
        assert "round-robin" in obs.description.lower() or "geo-DNS" in obs.description

    @patch("socket.getaddrinfo")
    async def test_partial_resolution(self, mock_getaddrinfo):
        """Only some random subdomains resolve -> still flagged.

        First call resolves, remaining two raise gaierror.
        """
        call_count = 0

        def _getaddrinfo(hostname, port, family):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0))]
            raise socket.gaierror("Name or service not known")

        mock_getaddrinfo.side_effect = _getaddrinfo
        check = WildcardDnsCheck()
        result = await check.run({"base_domain": "example.com"})

        wc = result.outputs["wildcard_dns"]
        assert wc["detected"] is True
        assert wc["probes_resolved"] == 1

    @patch("socket.getaddrinfo")
    async def test_non_wildcard_domain_produces_zero_observations(self, mock_getaddrinfo):
        """A domain where random subdomains do not resolve should produce
        no wildcard observations and report detected=False.

        This is the negative case: normal domains without wildcard DNS
        return NXDOMAIN for random subdomains.
        """
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        check = WildcardDnsCheck()
        result = await check.run({"base_domain": "legit-no-wildcard.com"})

        assert result.success is True
        wc = result.outputs["wildcard_dns"]
        assert wc["detected"] is False
        assert wc["ip"] is None
        assert len(result.observations) == 0
        # Confirm getaddrinfo was called for each probe
        assert mock_getaddrinfo.call_count == 3


# ═══════════════════════════════════════════════════════════════════════════════
# DnsRecordCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


def _resolver_side_effect(records: dict):
    """Return a side_effect callable for mock resolver.resolve().

    Args:
        records: mapping of record type (e.g. "MX") to list of mock rdata objects.
            Unlisted types raise NoAnswer.
    """
    import dns.resolver as _dns_resolver

    def _resolve(domain, rtype):
        if rtype in records:
            return records[rtype]
        raise _dns_resolver.NoAnswer()

    return _resolve


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

        mx_rdata = MagicMock()
        mx_rdata.to_text.return_value = "10 mail.example.com."
        mock_resolver.resolve.side_effect = _resolver_side_effect({"MX": [mx_rdata]})

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert result.success is True
        assert "mail.example.com" in result.outputs["dns_extra_hosts"]
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "MX record: mail.example.com (priority 10)"
        assert obs.severity == "info"
        assert obs.evidence == "MX 10 mail.example.com"

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_txt_spf_google(self, MockResolver):
        """SPF record with Google include is flagged."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        txt_rdata = MagicMock()
        txt_rdata.to_text.return_value = '"v=spf1 include:_spf.google.com ~all"'
        mock_resolver.resolve.side_effect = _resolver_side_effect({"TXT": [txt_rdata]})

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "SPF reveals providers: Google Workspace"
        assert obs.severity == "low"
        assert obs.evidence.startswith("TXT v=spf1 include:_spf.google.com")

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_txt_verification_token(self, MockResolver):
        """Verification tokens in TXT records are flagged."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        txt_rdata = MagicMock()
        txt_rdata.to_text.return_value = '"google-site-verification=abc123def456"'
        mock_resolver.resolve.side_effect = _resolver_side_effect({"TXT": [txt_rdata]})

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "TXT record: Google site verification token"
        assert obs.severity == "low"
        assert "google-site-verification=abc123def456" in obs.evidence

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_ns_record(self, MockResolver):
        """NS records generate info observations."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        ns_rdata = MagicMock()
        ns_rdata.to_text.return_value = "ns1.cloudflare.com."
        mock_resolver.resolve.side_effect = _resolver_side_effect({"NS": [ns_rdata]})

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "NS record: ns1.cloudflare.com"
        assert obs.severity == "info"
        assert obs.evidence == "NS ns1.cloudflare.com"

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_cname_extracted_as_extra_host(self, MockResolver):
        """CNAME targets are added to extra_hosts."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        cname_rdata = MagicMock()
        cname_rdata.to_text.return_value = "cdn.cloudfront.net."
        mock_resolver.resolve.side_effect = _resolver_side_effect({"CNAME": [cname_rdata]})

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert "cdn.cloudfront.net" in result.outputs["dns_extra_hosts"]
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "CNAME record: example.com -> cdn.cloudfront.net"
        assert obs.severity == "info"
        assert obs.evidence == "CNAME cdn.cloudfront.net"

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_aaaa_record(self, MockResolver):
        """AAAA records generate IPv6 observations."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        aaaa_rdata = MagicMock()
        aaaa_rdata.to_text.return_value = "2001:db8::1"
        mock_resolver.resolve.side_effect = _resolver_side_effect({"AAAA": [aaaa_rdata]})

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "IPv6 address: example.com -> 2001:db8::1"
        assert obs.severity == "info"
        assert obs.evidence == "AAAA 2001:db8::1"

    @pytest.mark.skipif(not HAS_DNSPYTHON, reason="dnspython not installed")
    @patch("app.checks.network.dns_records.dns.resolver.Resolver")
    async def test_soa_record(self, MockResolver):
        """SOA records generate info observations."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        soa_text = "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"
        soa_rdata = MagicMock()
        soa_rdata.to_text.return_value = soa_text
        mock_resolver.resolve.side_effect = _resolver_side_effect({"SOA": [soa_rdata]})

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "SOA record for example.com"
        assert obs.severity == "info"
        assert obs.evidence == f"SOA {soa_text}"

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

        mock_resolver.resolve.side_effect = _resolver_side_effect(
            {"MX": [mx_rdata], "NS": [ns_rdata]}
        )

        check = DnsRecordCheck()
        result = await check.run({"base_domain": "example.com"})

        assert "MX" in result.outputs["dns_extra_records"]
        assert "NS" in result.outputs["dns_extra_records"]
        assert len(result.observations) == 2
        titles = {obs.title for obs in result.observations}
        assert "MX record: mail.example.com (priority 10)" in titles
        assert "NS record: ns1.example.com" in titles


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
