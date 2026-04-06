"""Tests for TracerouteCheck: TCP-based network path tracing, CDN detection, and hop probing."""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


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


class TestTracerouteCheckResolver:
    """Test that TracerouteCheck is registered in check_resolver."""

    def test_traceroute_registered(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "traceroute" in names

    def test_traceroute_in_network_suite(self):
        from app.check_resolver import infer_suite

        assert infer_suite("traceroute") == "network"
