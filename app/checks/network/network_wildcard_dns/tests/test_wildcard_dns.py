"""Tests for network_wildcard_dns."""

import socket
from unittest.mock import patch

from app.checks.network.network_wildcard_dns import WildcardDnsCheck
from app.checks.network.network_wildcard_dns.check import _random_subdomain


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


async def probe_and_grade(check, context):
    """Run the probe, then the grading stage, and return the graded result.

    This check is split into probe + grade, so `run()` now
    returns candidates rather than observations. Tests assert on what an
    operator sees, which is what the grading stage produces — the same thing
    `CheckLauncher` calls immediately after `execute()`.
    """
    from app.grading import grade_result

    result = await check.run(context)
    return await grade_result(check, result, context)


class TestWildcardDnsCheckInit:
    """Tests for WildcardDnsCheck initialization."""

    def test_metadata(self):
        check = WildcardDnsCheck()
        assert check.name == "network_wildcard_dns"
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
        result = await probe_and_grade(check, {"base_domain": "example.com"})

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
        result = await probe_and_grade(check, {"base_domain": "example.com"})

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
        result = await probe_and_grade(check, {"base_domain": "example.com"})

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
        result = await probe_and_grade(check, {"base_domain": "example.com"})

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
        result = await probe_and_grade(check, {"base_domain": "legit-no-wildcard.com"})

        assert result.success is True
        wc = result.outputs["wildcard_dns"]
        assert wc["detected"] is False
        assert wc["ip"] is None
        assert len(result.observations) == 0
        # Confirm getaddrinfo was called for each probe
        assert mock_getaddrinfo.call_count == 3
