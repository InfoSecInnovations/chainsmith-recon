"""Tests for TracerouteCheck: TCP-based network path tracing, CDN detection, and hop probing."""

from unittest.mock import MagicMock, patch

import pytest

from app.checks.network.traceroute import CDN_PATTERNS, MAX_TARGETS, TracerouteCheck

# ---------------------------------------------------------------------------
# Helpers — build _probe_hop return sequences for controlled traces
# ---------------------------------------------------------------------------


def _hop(ttl, ip=None, hostname=None, rtt_ms=None):
    """Build a hop-info dict matching _probe_hop's return shape."""
    return {"hop": ttl, "ip": ip, "hostname": hostname, "rtt_ms": rtt_ms}


# ---------------------------------------------------------------------------
# Metadata / init tests
# ---------------------------------------------------------------------------


class TestTracerouteCheckInit:
    """Test TracerouteCheck metadata and initialization."""

    def test_check_metadata(self):
        check = TracerouteCheck()
        assert check.name == "traceroute"
        assert "TCP-based" in check.description

    def test_conditions_require_dns_records(self):
        check = TracerouteCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "dns_records"
        assert check.conditions[0].operator == "truthy"

    def test_produces_traceroute_data(self):
        check = TracerouteCheck()
        assert check.produces == ["traceroute_data"]

    def test_references_present(self):
        check = TracerouteCheck()
        assert any("PTES" in r for r in check.references)
        assert any("T1590" in r for r in check.references)

    def test_cdn_patterns_defined(self):
        assert "Cloudflare" in CDN_PATTERNS
        assert "Akamai" in CDN_PATTERNS
        assert "AWS CloudFront" in CDN_PATTERNS
        assert len(CDN_PATTERNS) >= 5


# ---------------------------------------------------------------------------
# Run-level tests — mock _probe_hop (I/O boundary), let _sync_trace_route
# and _trace_route execute for real so loop logic is exercised.
# ---------------------------------------------------------------------------


class TestTracerouteCheckRun:
    """Test TracerouteCheck.run() with _probe_hop mocked at the I/O boundary."""

    @pytest.mark.asyncio
    async def test_no_dns_records_fails(self):
        check = TracerouteCheck()
        result = await check.run({"dns_records": {}})
        assert result.success is False
        assert any("dns_records" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_empty_context_fails(self):
        check = TracerouteCheck()
        result = await check.run({})
        assert result.success is False

    @pytest.mark.asyncio
    async def test_basic_trace_three_hops(self):
        """3-hop trace: two timeouts then target reached. Real _sync_trace_route runs."""
        target_ip = "93.184.216.34"
        probe_results = [
            _hop(1, ip=None),  # TTL 1 — timeout (intermediate)
            _hop(2, ip=None),  # TTL 2 — timeout (intermediate)
            _hop(3, ip=target_ip, hostname=None, rtt_ms=12.5),  # reached
        ]
        call_idx = {"n": 0}

        def fake_probe_hop(tip, ttl):
            idx = call_idx["n"]
            call_idx["n"] += 1
            return probe_results[idx] if idx < len(probe_results) else _hop(ttl)

        check = TracerouteCheck()
        with (
            patch.object(check, "_probe_hop", side_effect=fake_probe_hop),
            patch("app.checks.network.traceroute.asyncio.sleep", return_value=None),
        ):
            context = {"dns_records": {"www.example.com": target_ip}}
            result = await check.run(context)

        assert result.success is True

        # traceroute_data structure
        td = result.outputs["traceroute_data"]
        assert "www.example.com" in td
        entry = td["www.example.com"]
        assert entry["target_ip"] == target_ip
        assert entry["total_hops"] == 3
        assert entry["reached_target"] is True
        assert entry["cdn_detected"] is None
        assert entry["avg_rtt_ms"] == 12.5
        assert len(entry["hops"]) == 3
        assert entry["hops"][0]["ip"] is None
        assert entry["hops"][2]["ip"] == target_ip

        # Exactly one observation: route summary (no CDN)
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Route to www.example.com: 3 hops, 12.5ms avg"
        assert obs.severity == "info"
        assert "www.example.com" in obs.evidence
        assert "Hops: 3" in obs.evidence
        assert "Reached: True" in obs.evidence

    @pytest.mark.asyncio
    async def test_traces_deduplicates_by_ip(self):
        """Two hostnames mapping to the same IP should only trace once."""
        target_ip = "1.2.3.4"
        call_count = {"n": 0}

        def fake_probe_hop(tip, ttl):
            call_count["n"] += 1
            return _hop(ttl, ip=target_ip, rtt_ms=5.0)

        check = TracerouteCheck()
        with (
            patch.object(check, "_probe_hop", side_effect=fake_probe_hop),
            patch("app.checks.network.traceroute.asyncio.sleep", return_value=None),
        ):
            context = {
                "dns_records": {
                    "www.example.com": target_ip,
                    "api.example.com": target_ip,  # same IP
                },
            }
            result = await check.run(context)

        assert result.success is True
        td = result.outputs["traceroute_data"]
        # Only one entry — deduped by IP
        assert len(td) == 1
        # _probe_hop called only once (1 hop to reach target for 1 unique IP)
        assert call_count["n"] == 1

    @pytest.mark.asyncio
    async def test_max_targets_limit(self):
        """More IPs than MAX_TARGETS should be capped."""

        def fake_probe_hop(tip, ttl):
            return _hop(ttl, ip=tip, rtt_ms=5.0)  # Direct reach

        check = TracerouteCheck()
        with (
            patch.object(check, "_probe_hop", side_effect=fake_probe_hop),
            patch("app.checks.network.traceroute.asyncio.sleep", return_value=None),
        ):
            dns_records = {f"host{i}.example.com": f"10.0.0.{i}" for i in range(20)}
            result = await check.run({"dns_records": dns_records})

        assert result.success is True
        assert len(result.outputs["traceroute_data"]) <= MAX_TARGETS

    @pytest.mark.asyncio
    async def test_trace_all_timeouts_stops_after_consecutive(self):
        """When all probes time out, the consecutive-timeout logic (3 in a row
        after hop 3) stops the trace early."""
        target_ip = "10.99.99.99"

        def fake_probe_hop(tip, ttl):
            return _hop(ttl, ip=None)  # always timeout

        check = TracerouteCheck()
        with (
            patch.object(check, "_probe_hop", side_effect=fake_probe_hop),
            patch("app.checks.network.traceroute.asyncio.sleep", return_value=None),
        ):
            result = await check.run({"dns_records": {"blocked.example.com": target_ip}})

        assert result.success is True
        td = result.outputs["traceroute_data"]
        assert "blocked.example.com" in td
        entry = td["blocked.example.com"]
        assert entry["reached_target"] is False
        # Should stop after 3 consecutive timeouts (at hop 3), not go to MAX_HOPS
        assert entry["total_hops"] <= 5  # generous upper bound; logic breaks at hop 3


# ---------------------------------------------------------------------------
# CDN detection (unit-level, no I/O)
# ---------------------------------------------------------------------------


class TestTracerouteCdnDetection:
    """Test CDN/WAF detection from hop hostnames."""

    def test_detect_cloudflare(self):
        check = TracerouteCheck()
        assert check._detect_cdn("edge01.cloudflare.net") == "Cloudflare"

    def test_detect_akamai(self):
        check = TracerouteCheck()
        assert check._detect_cdn("a23-50-52-1.deploy.akamai.net") == "Akamai"

    def test_detect_aws_cloudfront(self):
        check = TracerouteCheck()
        assert check._detect_cdn("server-52-85-1-1.iad89.r.cloudfront.net") == "AWS CloudFront"

    def test_detect_fastly(self):
        check = TracerouteCheck()
        assert check._detect_cdn("cache-iad-kcgs7200042.fastly.net") == "Fastly"

    def test_no_match_returns_none(self):
        check = TracerouteCheck()
        assert check._detect_cdn("router1.isp.net") is None

    def test_case_insensitive(self):
        check = TracerouteCheck()
        assert check._detect_cdn("EDGE01.CLOUDFLARE.NET") == "Cloudflare"


# ---------------------------------------------------------------------------
# Observation tests — _probe_hop mocked, real observation generation
# ---------------------------------------------------------------------------


class TestTracerouteObservations:
    """Test observation generation from traceroute results."""

    @pytest.mark.asyncio
    async def test_route_summary_observation_fields(self):
        """Route summary observation has exact title, severity, evidence."""
        target_ip = "93.184.216.34"
        probe_results = [
            _hop(1, ip=None),
            _hop(2, ip=None),
            _hop(3, ip=target_ip, rtt_ms=15.0),
        ]
        call_idx = {"n": 0}

        def fake_probe_hop(tip, ttl):
            idx = call_idx["n"]
            call_idx["n"] += 1
            return probe_results[idx] if idx < len(probe_results) else _hop(ttl)

        check = TracerouteCheck()
        with (
            patch.object(check, "_probe_hop", side_effect=fake_probe_hop),
            patch("app.checks.network.traceroute.asyncio.sleep", return_value=None),
        ):
            result = await check.run({"dns_records": {"www.example.com": target_ip}})

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.severity == "info"
        assert obs.title == "Route to www.example.com: 3 hops, 15.0ms avg"
        assert "Hops: 3" in obs.evidence
        assert "Reached: True" in obs.evidence
        assert "www.example.com" in obs.description
        assert target_ip in obs.description

    @pytest.mark.asyncio
    async def test_cdn_observation_when_cloudflare_in_path(self):
        """CDN hop produces a second observation with provider name in title."""
        target_ip = "104.16.100.1"
        probe_results = [
            _hop(1, ip=None),
            _hop(2, ip="104.16.1.1", hostname="edge.cloudflare.net", rtt_ms=5.0),
            _hop(3, ip=target_ip, rtt_ms=10.0),
        ]
        call_idx = {"n": 0}

        def fake_probe_hop(tip, ttl):
            idx = call_idx["n"]
            call_idx["n"] += 1
            return probe_results[idx] if idx < len(probe_results) else _hop(ttl)

        check = TracerouteCheck()
        with (
            patch.object(check, "_probe_hop", side_effect=fake_probe_hop),
            patch("app.checks.network.traceroute.asyncio.sleep", return_value=None),
        ):
            result = await check.run({"dns_records": {"cdn-site.example.com": target_ip}})

        # Two observations: route summary + CDN
        assert len(result.observations) == 2
        route_obs = result.observations[0]
        cdn_obs = result.observations[1]

        assert route_obs.title.startswith("Route to cdn-site.example.com:")
        assert "3 hops" in route_obs.title
        assert route_obs.severity == "info"

        assert cdn_obs.title == "CDN detected in path to cdn-site.example.com: Cloudflare (hop 2)"
        assert cdn_obs.severity == "info"
        assert "Cloudflare" in cdn_obs.evidence
        assert "cdn-site.example.com" in cdn_obs.evidence

    @pytest.mark.asyncio
    async def test_no_observations_when_trace_returns_none(self):
        """When _trace_route returns None (e.g. timeout), no observations."""
        check = TracerouteCheck()
        # Force _trace_route to time out by making the executor raise
        with (
            patch.object(check, "_sync_trace_route", side_effect=Exception("boom")),
            patch("app.checks.network.traceroute.asyncio.sleep", return_value=None),
        ):
            result = await check.run({"dns_records": {"fail.example.com": "10.0.0.1"}})

        assert result.success is True
        assert len(result.observations) == 0
        assert result.outputs["traceroute_data"] == {}


# ---------------------------------------------------------------------------
# Negative / edge-case tests
# ---------------------------------------------------------------------------


class TestTracerouteEdgeCases:
    """Edge cases: single-hop local, probe structure."""

    @pytest.mark.asyncio
    async def test_single_hop_local_network(self):
        """A trace that reaches the target in 1 hop (local network)
        should produce exactly 1 observation with minimal hops."""
        target_ip = "192.168.1.50"

        def fake_probe_hop(tip, ttl):
            return _hop(ttl, ip=target_ip, rtt_ms=0.5)

        check = TracerouteCheck()
        with (
            patch.object(check, "_probe_hop", side_effect=fake_probe_hop),
            patch("app.checks.network.traceroute.asyncio.sleep", return_value=None),
        ):
            result = await check.run({"dns_records": {"local-server": target_ip}})

        assert result.success is True
        td = result.outputs["traceroute_data"]
        entry = td["local-server"]
        assert entry["total_hops"] == 1
        assert entry["reached_target"] is True
        assert entry["cdn_detected"] is None

        # Exactly one observation (route summary), no CDN observation
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Route to local-server: 1 hops, 0.5ms avg"
        assert obs.severity == "info"

    def test_probe_hop_returns_correct_structure_on_connect_refused(self):
        """_probe_hop returns dict with all expected keys on connection-refused."""
        check = TracerouteCheck()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(111, "Connection refused")

        with (
            patch("app.checks.network.traceroute.socket.socket", return_value=mock_sock),
            patch(
                "app.checks.network.traceroute.socket.gethostbyaddr",
                side_effect=OSError("no PTR"),
            ),
        ):
            hop = check._probe_hop("1.2.3.4", 5)

        assert hop["hop"] == 5
        assert hop["ip"] == "1.2.3.4"  # connection-refused means we reached the IP
        assert isinstance(hop["rtt_ms"], float)
        assert hop["hostname"] is None  # gethostbyaddr failed

    def test_probe_hop_timeout_returns_none_ip(self):
        """A timeout at a hop returns ip=None."""
        check = TracerouteCheck()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = TimeoutError("timed out")

        with patch("app.checks.network.traceroute.socket.socket", return_value=mock_sock):
            hop = check._probe_hop("10.0.0.1", 3)

        assert hop["hop"] == 3
        assert hop["ip"] is None
        assert hop["rtt_ms"] is None
        assert hop["hostname"] is None

    def test_probe_hop_successful_connect(self):
        """A successful connect sets ip to target_ip with rtt."""
        check = TracerouteCheck()
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None  # success

        with (
            patch("app.checks.network.traceroute.socket.socket", return_value=mock_sock),
            patch(
                "app.checks.network.traceroute.socket.gethostbyaddr",
                return_value=("target.example.com", [], ["1.2.3.4"]),
            ),
        ):
            hop = check._probe_hop("1.2.3.4", 2)

        assert hop["hop"] == 2
        assert hop["ip"] == "1.2.3.4"
        assert isinstance(hop["rtt_ms"], float)
        assert hop["hostname"] == "target.example.com"


# ---------------------------------------------------------------------------
# Check resolver registration
# ---------------------------------------------------------------------------


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
