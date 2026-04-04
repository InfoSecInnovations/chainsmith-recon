"""
tests/checks/test_network_phase7d.py

Tests for Phase 7d network checks:
- WhoisLookupCheck (check 8): WHOIS domain registration and ASN/RDAP lookup
- TracerouteCheck (check 9): TCP-based network path tracing
- IPv6DiscoveryCheck (check 10): IPv6 AAAA resolution and dual-stack analysis
"""

import socket
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════
# WHOIS Lookup Check Tests
# ═══════════════════════════════════════════════════════════════════


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


class TestWhoisDomainFindings:
    """Test finding generation from domain WHOIS data."""

    @pytest.mark.asyncio
    async def test_registration_info_finding(self):
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
            info_findings = [f for f in result.findings if f.severity == "info"]
            assert any("registrar" in f.title.lower() for f in info_findings)

    @pytest.mark.asyncio
    async def test_recent_registration_finding(self):
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
            low_findings = [f for f in result.findings if f.severity == "low"]
            assert any(
                "registered within" in f.title.lower() or "90 days" in f.title for f in low_findings
            )

    @pytest.mark.asyncio
    async def test_redacted_finding(self):
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
            assert any("redacted" in f.title.lower() for f in result.findings)


class TestWhoisAsnFindings:
    """Test finding generation from ASN/RDAP data."""

    @pytest.mark.asyncio
    async def test_asn_info_finding(self):
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
            info_findings = [f for f in result.findings if f.severity == "info"]
            assert any("AS16509" in f.title for f in info_findings)

    @pytest.mark.asyncio
    async def test_private_ip_finding(self):
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
            assert any("private" in f.title.lower() for f in result.findings)

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


# ═══════════════════════════════════════════════════════════════════
# Traceroute Check Tests
# ═══════════════════════════════════════════════════════════════════


class TestTracerouteCheckInit:
    """Test TracerouteCheck metadata and initialization."""

    def test_check_metadata(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        assert check.name == "traceroute"
        assert "trace" in check.description.lower() or "path" in check.description.lower()

    def test_conditions(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "dns_records"
        assert check.conditions[0].operator == "truthy"

    def test_produces(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        assert "traceroute_data" in check.produces

    def test_references(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        assert len(check.references) > 0

    def test_cdn_patterns_defined(self):
        from app.checks.network.traceroute import CDN_PATTERNS

        assert "Cloudflare" in CDN_PATTERNS
        assert "Akamai" in CDN_PATTERNS
        assert "AWS CloudFront" in CDN_PATTERNS
        assert len(CDN_PATTERNS) >= 5

    def test_max_hops_reasonable(self):
        from app.checks.network.traceroute import MAX_HOPS

        assert 10 <= MAX_HOPS <= 64


class TestTracerouteCheckRun:
    """Test TracerouteCheck runtime behavior."""

    @pytest.mark.asyncio
    async def test_no_dns_records_fails(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        result = await check.run({"dns_records": {}})
        assert result.success is False

    @pytest.mark.asyncio
    async def test_empty_context_fails(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        result = await check.run({})
        assert result.success is False

    @pytest.mark.asyncio
    async def test_traces_unique_ips(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        with patch.object(check, "_trace_route", new_callable=AsyncMock) as mock_trace:
            mock_trace.return_value = {
                "target_ip": "1.2.3.4",
                "hops": [
                    {"hop": 1, "ip": "192.168.1.1", "hostname": "gateway", "rtt_ms": 1.0},
                    {"hop": 2, "ip": "1.2.3.4", "hostname": None, "rtt_ms": 10.0},
                ],
                "total_hops": 2,
                "cdn_detected": None,
                "avg_rtt_ms": 5.5,
                "reached_target": True,
            }
            context = {
                "dns_records": {
                    "www.example.com": "1.2.3.4",
                    "api.example.com": "1.2.3.4",  # Same IP
                },
            }
            result = await check.run(context)
            assert result.success is True
            # Same IP — should trace only once
            assert mock_trace.call_count == 1

    @pytest.mark.asyncio
    async def test_outputs_traceroute_data(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        with patch.object(check, "_trace_route", new_callable=AsyncMock) as mock_trace:
            mock_trace.return_value = {
                "target_ip": "1.2.3.4",
                "hops": [{"hop": 1, "ip": "1.2.3.4", "hostname": None, "rtt_ms": 5.0}],
                "total_hops": 1,
                "cdn_detected": None,
                "avg_rtt_ms": 5.0,
                "reached_target": True,
            }
            context = {"dns_records": {"www.example.com": "1.2.3.4"}}
            result = await check.run(context)
            assert "traceroute_data" in result.outputs

    @pytest.mark.asyncio
    async def test_max_targets_limit(self):
        from app.checks.network.traceroute import MAX_TARGETS, TracerouteCheck

        check = TracerouteCheck()
        with patch.object(check, "_trace_route", new_callable=AsyncMock) as mock_trace:
            mock_trace.return_value = {
                "target_ip": "x",
                "hops": [],
                "total_hops": 0,
                "cdn_detected": None,
                "avg_rtt_ms": None,
                "reached_target": False,
            }
            # Create more hosts than MAX_TARGETS
            dns_records = {f"host{i}.example.com": f"10.0.0.{i}" for i in range(20)}
            context = {"dns_records": dns_records}
            await check.run(context)
            assert mock_trace.call_count <= MAX_TARGETS


class TestTracerouteCdnDetection:
    """Test CDN/WAF detection from hop hostnames."""

    def test_detect_cloudflare(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        assert check._detect_cdn("edge01.cloudflare.net") == "Cloudflare"

    def test_detect_akamai(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        assert check._detect_cdn("a23-50-52-1.deploy.akamai.net") == "Akamai"

    def test_detect_aws_cloudfront(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        assert check._detect_cdn("server-52-85-1-1.iad89.r.cloudfront.net") == "AWS CloudFront"

    def test_detect_fastly(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        assert check._detect_cdn("cache-iad-kcgs7200042.fastly.net") == "Fastly"

    def test_no_match_returns_none(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        assert check._detect_cdn("router1.isp.net") is None

    def test_case_insensitive(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        assert check._detect_cdn("EDGE01.CLOUDFLARE.NET") == "Cloudflare"


class TestTracerouteFindings:
    """Test finding generation from traceroute results."""

    @pytest.mark.asyncio
    async def test_route_info_finding(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        with patch.object(check, "_trace_route", new_callable=AsyncMock) as mock_trace:
            mock_trace.return_value = {
                "target_ip": "1.2.3.4",
                "hops": [
                    {"hop": 1, "ip": "192.168.1.1", "hostname": "gw.local", "rtt_ms": 1.0},
                    {"hop": 2, "ip": "1.2.3.4", "hostname": None, "rtt_ms": 10.0},
                ],
                "total_hops": 2,
                "cdn_detected": None,
                "avg_rtt_ms": 5.5,
                "reached_target": True,
            }
            context = {"dns_records": {"www.example.com": "1.2.3.4"}}
            result = await check.run(context)
            info_findings = [f for f in result.findings if f.severity == "info"]
            assert any("route" in f.title.lower() for f in info_findings)

    @pytest.mark.asyncio
    async def test_cdn_detected_finding(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        with patch.object(check, "_trace_route", new_callable=AsyncMock) as mock_trace:
            mock_trace.return_value = {
                "target_ip": "1.2.3.4",
                "hops": [
                    {"hop": 1, "ip": "192.168.1.1", "hostname": "gw.local", "rtt_ms": 1.0},
                    {
                        "hop": 2,
                        "ip": "104.16.1.1",
                        "hostname": "edge.cloudflare.net",
                        "rtt_ms": 5.0,
                    },
                    {"hop": 3, "ip": "1.2.3.4", "hostname": None, "rtt_ms": 10.0},
                ],
                "total_hops": 3,
                "cdn_detected": "Cloudflare",
                "avg_rtt_ms": 5.3,
                "reached_target": True,
            }
            context = {"dns_records": {"www.example.com": "1.2.3.4"}}
            result = await check.run(context)
            assert any(
                "cdn" in f.title.lower() and "cloudflare" in f.title.lower()
                for f in result.findings
            )

    @pytest.mark.asyncio
    async def test_no_findings_when_trace_fails(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        with patch.object(check, "_trace_route", new_callable=AsyncMock) as mock_trace:
            mock_trace.return_value = None
            context = {"dns_records": {"www.example.com": "1.2.3.4"}}
            result = await check.run(context)
            assert len(result.findings) == 0


class TestTracerouteProbeHop:
    """Test individual hop probing."""

    def test_probe_hop_timeout(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        # Probe an unreachable IP — should timeout and return None ip
        with patch("app.checks.network.traceroute.HOP_TIMEOUT", 0.1):
            hop = check._probe_hop("192.0.2.1", 1)  # TEST-NET, should timeout
            assert hop["hop"] == 1
            # ip may or may not be None depending on network

    def test_probe_hop_structure(self):
        from app.checks.network.traceroute import TracerouteCheck

        check = TracerouteCheck()
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_socket_cls.return_value = mock_sock
            mock_sock.connect.side_effect = OSError(111, "Connection refused")

            hop = check._probe_hop("1.2.3.4", 5)
            assert "hop" in hop
            assert "ip" in hop
            assert "hostname" in hop
            assert "rtt_ms" in hop
            assert hop["hop"] == 5


# ═══════════════════════════════════════════════════════════════════
# IPv6 Discovery Check Tests
# ═══════════════════════════════════════════════════════════════════


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


# ═══════════════════════════════════════════════════════════════════
# Check Resolver Integration Tests
# ═══════════════════════════════════════════════════════════════════


class TestPhase7dCheckResolver:
    """Test that Phase 7d checks are registered in check_resolver."""

    def test_whois_lookup_registered(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "whois_lookup" in names

    def test_traceroute_registered(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "traceroute" in names

    def test_ipv6_discovery_registered(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "ipv6_discovery" in names

    def test_whois_in_network_suite(self):
        from app.check_resolver import infer_suite

        assert infer_suite("whois_lookup") == "network"

    def test_traceroute_in_network_suite(self):
        from app.check_resolver import infer_suite

        assert infer_suite("traceroute") == "network"

    def test_ipv6_discovery_in_network_suite(self):
        from app.check_resolver import infer_suite

        assert infer_suite("ipv6_discovery") == "network"

    def test_total_check_count(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        # Was 43 checks (Phase 7c), now +3 = 46
        assert len(checks) >= 46
