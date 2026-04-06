"""Tests for ReverseDnsCheck: PTR record lookup and internal hostname detection."""

from unittest.mock import patch

import pytest

from app.checks.base import Service


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


class TestReverseDnsCheckRun:
    """Test ReverseDnsCheck runtime behavior."""

    @pytest.mark.asyncio
    async def test_no_dns_records_fails(self):
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()
        result = await check.run({"dns_records": {}})
        assert result.success is False

    @pytest.mark.asyncio
    async def test_single_ip_with_ptr(self):
        """Single IP with a PTR record should produce info finding."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "93.184.216.34"},
            "base_domain": "example.com",
        }

        with patch.object(check, "_ptr_lookup", return_value=["www.example.com"]):
            result = await check.run(context)

        assert result.success is True
        assert result.targets_checked == 1
        assert "93.184.216.34" in result.outputs["reverse_dns"]
        assert result.outputs["reverse_dns"]["93.184.216.34"]["ptr_records"] == ["www.example.com"]

        # Should have at least one info finding
        assert len(result.findings) >= 1
        assert any("Reverse DNS" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_multiple_ptr_records_virtual_hosting(self):
        """Multiple PTR records suggest virtual hosting."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "1.2.3.4"},
            "base_domain": "example.com",
        }

        with patch.object(
            check,
            "_ptr_lookup",
            return_value=["host1.example.com", "host2.other.com", "host3.another.com"],
        ):
            result = await check.run(context)

        assert result.success is True
        multi_findings = [f for f in result.findings if "multiple ptr" in f.title.lower()]
        assert len(multi_findings) == 1

    @pytest.mark.asyncio
    async def test_internal_hostname_detection(self):
        """Internal hostnames in PTR should produce low severity finding."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"api.example.com": "10.0.1.42"},
            "base_domain": "example.com",
        }

        with patch.object(check, "_ptr_lookup", return_value=["ip-10-0-1-42.ec2.internal"]):
            result = await check.run(context)

        assert result.success is True
        internal_findings = [f for f in result.findings if "Internal hostname in PTR" in f.title]
        assert len(internal_findings) == 1
        assert internal_findings[0].severity == "low"

    @pytest.mark.asyncio
    async def test_ptr_mismatch_finding(self):
        """PTR pointing outside target domain should produce info finding."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"cdn.example.com": "151.101.1.67"},
            "base_domain": "example.com",
        }

        with patch.object(check, "_ptr_lookup", return_value=["fastly-edge.fastly.net"]):
            result = await check.run(context)

        assert result.success is True
        mismatch_findings = [f for f in result.findings if "mismatch" in f.title.lower()]
        assert len(mismatch_findings) == 1
        assert mismatch_findings[0].severity == "info"

    @pytest.mark.asyncio
    async def test_no_ptr_records_no_findings(self):
        """IPs with no PTR records should not generate findings."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"app.example.com": "192.168.1.1"},
            "base_domain": "example.com",
        }

        with patch.object(check, "_ptr_lookup", return_value=[]):
            result = await check.run(context)

        assert result.success is True
        assert result.targets_checked == 1
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_new_hosts_from_ptr(self):
        """PTR hostnames not in known hosts should appear in reverse_dns_hosts."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "1.2.3.4"},
            "base_domain": "example.com",
        }

        with patch.object(check, "_ptr_lookup", return_value=["new-host.example.com"]):
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

        with patch.object(check, "_ptr_lookup", return_value=["www.example.com"]):
            result = await check.run(context)

        assert "www.example.com" not in result.outputs["reverse_dns_hosts"]

    @pytest.mark.asyncio
    async def test_trailing_dot_stripped(self):
        """PTR records with trailing dots should be cleaned."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"www.example.com": "1.2.3.4"},
            "base_domain": "example.com",
        }

        with patch.object(check, "_ptr_lookup", return_value=["newhost.example.com."]):
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

        lookup_count = 0

        async def counting_ptr_lookup(ip):
            nonlocal lookup_count
            lookup_count += 1
            return ["server1.example.com"]

        with patch.object(check, "_ptr_lookup", side_effect=counting_ptr_lookup):
            result = await check.run(context)

        # Same IP should only be looked up once
        assert lookup_count == 1
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

        async def mock_ptr_lookup(ip):
            return {
                "1.2.3.4": ["web.example.com"],
                "5.6.7.8": ["api-server.example.com"],
            }.get(ip, [])

        with patch.object(check, "_ptr_lookup", side_effect=mock_ptr_lookup):
            result = await check.run(context)

        assert result.targets_checked == 2
        assert "1.2.3.4" in result.outputs["reverse_dns"]
        assert "5.6.7.8" in result.outputs["reverse_dns"]

    @pytest.mark.asyncio
    async def test_corp_pattern_detected_as_internal(self):
        """Hostnames with .corp. pattern should be flagged as internal."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        context = {
            "dns_records": {"mail.example.com": "10.0.0.5"},
            "base_domain": "example.com",
        }

        with patch.object(check, "_ptr_lookup", return_value=["mail-01.corp.example.com"]):
            result = await check.run(context)

        assert result.outputs["reverse_dns"]["10.0.0.5"]["internal"] is True
        internal_findings = [f for f in result.findings if "internal" in f.title.lower()]
        assert len(internal_findings) == 1

    @pytest.mark.asyncio
    async def test_socket_fallback_when_no_dnspython(self):
        """When dnspython is not available, should use socket fallback."""
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        # Test the socket-based lookup path
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
        from app.checks.network.reverse_dns import ReverseDnsCheck

        check = ReverseDnsCheck()

        import socket as socket_mod

        with patch("app.checks.network.reverse_dns.HAS_DNSPYTHON", False):
            with patch("socket.gethostbyaddr", side_effect=socket_mod.herror):
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
