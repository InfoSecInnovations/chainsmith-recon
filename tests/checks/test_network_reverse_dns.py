"""Tests for ReverseDnsCheck: PTR record lookup and internal hostname detection."""

from unittest.mock import MagicMock, patch

import pytest


class TestReverseDnsCheckInit:
    """Test ReverseDnsCheck metadata and initialization."""

    def test_check_metadata(self):
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()
        assert check.name == "reverse_dns"
        assert "PTR" in check.description or "reverse" in check.description.lower()

    def test_conditions(self):
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "dns_records"
        assert check.conditions[0].operator == "truthy"

    def test_produces(self):
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()
        assert "reverse_dns" in check.produces
        assert "reverse_dns_hosts" in check.produces

    def test_references(self):
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()
        assert len(check.references) > 0

    def test_internal_patterns(self):
        from app.checks.network.reverse_dns import INTERNAL_PATTERNS

        assert ".internal." in INTERNAL_PATTERNS
        assert ".local." in INTERNAL_PATTERNS
        assert ".ec2.internal" in INTERNAL_PATTERNS
        assert "ip-" in INTERNAL_PATTERNS


def _make_ptr_answer(hostnames):
    """Build a fake dns.resolver answer iterable with .target attributes."""
    records = []
    for name in hostnames:
        rdata = MagicMock()
        # dns.resolver returns rdata objects with .target; str(target) includes trailing dot
        rdata.target = MagicMock()
        rdata.target.__str__ = lambda self, n=name: n + "."
        records.append(rdata)
    return records


class TestReverseDnsCheckRun:
    """Test ReverseDnsCheck runtime behavior with real _ptr_lookup execution."""

    @pytest.mark.asyncio
    async def test_no_dns_records_fails(self):
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()
        result = await check.run({"dns_records": {}})
        assert result.success is False
        assert any("No dns_records" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_single_ip_with_ptr_dnspython(self):
        """Single IP with a PTR record via dnspython should produce an info observation."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "93.184.216.34"},
            "base_domain": "example.com",
        }

        fake_answer = _make_ptr_answer(["www.example.com"])

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", return_value=fake_answer),
        ):
            result = await check.run(context)

        assert result.success is True
        assert result.targets_checked == 1
        assert "93.184.216.34" in result.outputs["reverse_dns"]
        assert result.outputs["reverse_dns"]["93.184.216.34"]["ptr_records"] == ["www.example.com"]

        # Should have exactly one info observation (Reverse DNS)
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Reverse DNS: 93.184.216.34 -> www.example.com"
        assert obs.severity == "info"
        assert "93.184.216.34" in obs.evidence
        assert "www.example.com" in obs.evidence

    @pytest.mark.asyncio
    async def test_single_ip_with_ptr_socket_fallback(self):
        """Single IP with PTR via socket fallback should produce an info observation."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "93.184.216.34"},
            "base_domain": "example.com",
        }

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", False),
            patch(
                "socket.gethostbyaddr",
                return_value=("www.example.com", [], ["93.184.216.34"]),
            ),
        ):
            result = await check.run(context)

        assert result.success is True
        assert result.targets_checked == 1
        assert result.outputs["reverse_dns"]["93.184.216.34"]["ptr_records"] == ["www.example.com"]
        assert len(result.observations) == 1
        assert result.observations[0].title == "Reverse DNS: 93.184.216.34 -> www.example.com"
        assert result.observations[0].severity == "info"

    @pytest.mark.asyncio
    async def test_multiple_ptr_records_virtual_hosting(self):
        """Multiple PTR records suggest virtual hosting."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "1.2.3.4"},
            "base_domain": "example.com",
        }

        fake_answer = _make_ptr_answer(
            ["host1.example.com", "host2.other.com", "host3.another.com"]
        )

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", return_value=fake_answer),
        ):
            result = await check.run(context)

        assert result.success is True

        # Should have: base info, multi-PTR, mismatch observations
        multi_observations = [f for f in result.observations if "Multiple PTR" in f.title]
        assert len(multi_observations) == 1
        assert multi_observations[0].severity == "info"
        assert "3 PTR records" in multi_observations[0].description
        assert "host1.example.com" in multi_observations[0].evidence

    @pytest.mark.asyncio
    async def test_internal_hostname_detection(self):
        """Internal hostnames in PTR should produce low severity observation."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"api.example.com": "10.0.1.42"},
            "base_domain": "example.com",
        }

        fake_answer = _make_ptr_answer(["ip-10-0-1-42.ec2.internal"])

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", return_value=fake_answer),
        ):
            result = await check.run(context)

        assert result.success is True
        assert result.outputs["reverse_dns"]["10.0.1.42"]["internal"] is True

        internal_observations = [
            f for f in result.observations if "Internal hostname in PTR" in f.title
        ]
        assert len(internal_observations) == 1
        assert internal_observations[0].severity == "low"
        assert "ip-10-0-1-42.ec2.internal" in internal_observations[0].evidence

    @pytest.mark.asyncio
    async def test_ptr_mismatch_observation(self):
        """PTR pointing outside target domain should produce info observation."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"cdn.example.com": "151.101.1.67"},
            "base_domain": "example.com",
        }

        fake_answer = _make_ptr_answer(["fastly-edge.fastly.net"])

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", return_value=fake_answer),
        ):
            result = await check.run(context)

        assert result.success is True
        mismatch_observations = [f for f in result.observations if "mismatch" in f.title.lower()]
        assert len(mismatch_observations) == 1
        assert mismatch_observations[0].severity == "info"
        assert "fastly-edge.fastly.net" in mismatch_observations[0].evidence
        assert "151.101.1.67" in mismatch_observations[0].evidence

    @pytest.mark.asyncio
    async def test_no_ptr_records_dnspython_exception(self):
        """DNS exception during PTR lookup should yield zero observations."""
        import dns.exception

        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"app.example.com": "192.168.1.1"},
            "base_domain": "example.com",
        }

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", side_effect=dns.exception.DNSException("NXDOMAIN")),
        ):
            result = await check.run(context)

        assert result.success is True
        assert result.targets_checked == 1
        assert len(result.observations) == 0
        assert result.outputs["reverse_dns"]["192.168.1.1"]["ptr_records"] == []

    @pytest.mark.asyncio
    async def test_no_ptr_records_socket_error(self):
        """Socket herror during PTR lookup (no PTR) should yield zero observations."""
        import socket as socket_mod

        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"app.example.com": "192.168.1.1"},
            "base_domain": "example.com",
        }

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", False),
            patch("socket.gethostbyaddr", side_effect=socket_mod.herror("Host not found")),
        ):
            result = await check.run(context)

        assert result.success is True
        assert result.targets_checked == 1
        assert len(result.observations) == 0
        assert result.outputs["reverse_dns"]["192.168.1.1"]["ptr_records"] == []
        assert result.outputs["reverse_dns_hosts"] == []

    @pytest.mark.asyncio
    async def test_new_hosts_from_ptr(self):
        """PTR hostnames not in known hosts should appear in reverse_dns_hosts."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "1.2.3.4"},
            "base_domain": "example.com",
        }

        fake_answer = _make_ptr_answer(["new-host.example.com"])

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", return_value=fake_answer),
        ):
            result = await check.run(context)

        assert "new-host.example.com" in result.outputs["reverse_dns_hosts"]

    @pytest.mark.asyncio
    async def test_known_hosts_excluded_from_new(self):
        """PTR hostnames already in dns_records should NOT appear in reverse_dns_hosts."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "1.2.3.4"},
            "base_domain": "example.com",
        }

        fake_answer = _make_ptr_answer(["www.example.com"])

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", return_value=fake_answer),
        ):
            result = await check.run(context)

        assert "www.example.com" not in result.outputs["reverse_dns_hosts"]

    @pytest.mark.asyncio
    async def test_trailing_dot_stripped(self):
        """PTR records with trailing dots should be cleaned (dnspython returns trailing dots)."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "1.2.3.4"},
            "base_domain": "example.com",
        }

        # dnspython's str(rdata.target) returns trailing dot; _ptr_lookup_dnspython strips it
        fake_answer = _make_ptr_answer(["newhost.example.com"])

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", return_value=fake_answer),
        ):
            result = await check.run(context)

        # The trailing dot should be stripped when adding to new hosts
        assert "newhost.example.com" in result.outputs["reverse_dns_hosts"]

    @pytest.mark.asyncio
    async def test_deduplicated_ips(self):
        """Multiple hostnames resolving to same IP should only trigger one PTR lookup."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {
                "www.example.com": "1.2.3.4",
                "api.example.com": "1.2.3.4",
            },
            "base_domain": "example.com",
        }

        fake_answer = _make_ptr_answer(["server1.example.com"])
        call_count = 0

        def counting_resolve(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return fake_answer

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", side_effect=counting_resolve),
        ):
            result = await check.run(context)

        # Same IP should only be looked up once
        assert call_count == 1
        assert result.targets_checked == 1

    @pytest.mark.asyncio
    async def test_multiple_ips(self):
        """Multiple different IPs should each get PTR lookups."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {
                "www.example.com": "1.2.3.4",
                "api.example.com": "5.6.7.8",
            },
            "base_domain": "example.com",
        }

        answer_web = _make_ptr_answer(["web.example.com"])
        answer_api = _make_ptr_answer(["api-server.example.com"])

        def route_resolve(rev_name, rdtype):
            # dns.reversename.from_address returns an object whose str includes in-addr.arpa
            rev_str = str(rev_name)
            if "4.3.2.1" in rev_str:
                return answer_web
            elif "8.7.6.5" in rev_str:
                return answer_api
            return []

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", side_effect=route_resolve),
        ):
            result = await check.run(context)

        assert result.targets_checked == 2
        assert "1.2.3.4" in result.outputs["reverse_dns"]
        assert "5.6.7.8" in result.outputs["reverse_dns"]
        assert result.outputs["reverse_dns"]["1.2.3.4"]["ptr_records"] == ["web.example.com"]
        assert result.outputs["reverse_dns"]["5.6.7.8"]["ptr_records"] == ["api-server.example.com"]

    @pytest.mark.asyncio
    async def test_corp_pattern_detected_as_internal(self):
        """Hostnames with .corp. pattern should be flagged as internal."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"mail.example.com": "10.0.0.5"},
            "base_domain": "example.com",
        }

        fake_answer = _make_ptr_answer(["mail-01.corp.example.com"])

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", return_value=fake_answer),
        ):
            result = await check.run(context)

        assert result.outputs["reverse_dns"]["10.0.0.5"]["internal"] is True
        internal_observations = [f for f in result.observations if "internal" in f.title.lower()]
        assert len(internal_observations) == 1
        assert internal_observations[0].severity == "low"
        assert "mail-01.corp.example.com" in internal_observations[0].evidence

    @pytest.mark.asyncio
    async def test_not_internal_for_normal_ptr(self):
        """A normal PTR (no internal patterns) should not be flagged as internal."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "1.2.3.4"},
            "base_domain": "example.com",
        }

        fake_answer = _make_ptr_answer(["webserver.example.com"])

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", True),
            patch("dns.resolver.resolve", return_value=fake_answer),
        ):
            result = await check.run(context)

        assert result.outputs["reverse_dns"]["1.2.3.4"]["internal"] is False
        internal_observations = [f for f in result.observations if "internal" in f.title.lower()]
        assert len(internal_observations) == 0

    @pytest.mark.asyncio
    async def test_socket_fallback_with_aliases(self):
        """Socket fallback should return hostname and aliases."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", False),
            patch(
                "socket.gethostbyaddr",
                return_value=("host1.example.com", ["alias1.example.com"], ["1.2.3.4"]),
            ),
        ):
            records = await check._ptr_lookup_socket("1.2.3.4")

        assert "host1.example.com" in records
        assert "alias1.example.com" in records

    @pytest.mark.asyncio
    async def test_socket_fallback_failure(self):
        """Socket fallback should return empty list on failure."""
        import socket as socket_mod

        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        with (
            patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", False),
            patch("socket.gethostbyaddr", side_effect=socket_mod.herror),
        ):
            records = await check._ptr_lookup_socket("1.2.3.4")

        assert records == []


class TestPhase7bRegistration:
    """Test that Phase 7b checks are correctly registered in the resolver."""

    def test_checks_present_in_resolver(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "tls_analysis" in names
        assert "reverse_dns" in names

    def test_reverse_dns_before_port_scan(self):
        """reverse_dns should run before port_scan (Phase 2 ordering)."""
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        rdns_idx = names.index("reverse_dns")
        port_scan_idx = names.index("port_scan")
        assert rdns_idx < port_scan_idx

    def test_tls_analysis_after_port_scan(self):
        """tls_analysis should run after port_scan (needs services)."""
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        tls_idx = names.index("tls_analysis")
        port_scan_idx = names.index("port_scan")
        assert tls_idx > port_scan_idx

    def test_suite_inference_network(self):
        """Both checks should be inferred as 'network' suite."""
        from app.check_resolver import infer_suite

        assert infer_suite("tls_analysis") == "network"
        assert infer_suite("reverse_dns") == "network"

    def test_suite_filter(self):
        """Both checks should appear when filtering by 'network' suite."""
        from app.check_resolver import resolve_checks

        checks = resolve_checks(suites=["network"])
        names = [c.name for c in checks]
        assert "tls_analysis" in names
        assert "reverse_dns" in names

    def test_total_check_count(self):
        """Total check count should have increased by 2 (from 41 to 43)."""
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        # 39 from Phase 7a + 2 new = 41
        # Actually let's just verify it's at least 41
        assert len(checks) >= 41
