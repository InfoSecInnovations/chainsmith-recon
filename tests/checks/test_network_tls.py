"""Tests for TlsAnalysisCheck: TLS handshake, certificate, and cipher analysis.

Mock strategy: ``_get_cert_info`` and ``_probe_protocols`` are mocked because
they perform real SSL/TLS handshakes (ssl.create_default_context, wrap_socket,
getpeercert) and per-protocol probing with separate SSLContext instances.
Faithfully reproducing the SSL state machine in a unit test is impractical.

To compensate:
  - ``_parse_dn`` and ``_parse_cert_date`` are tested directly (no mocking).
  - All run-level tests make specific assertions on observation titles,
    severities, and evidence content rather than just ``result.success``.
  - Tautological tests (asserting success after mocking out all logic) have
    been removed or replaced with meaningful checks.
"""

import datetime
from unittest.mock import patch

import pytest

from app.checks.base import Service

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _future_iso(days: int = 365) -> str:
    return (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=days)).isoformat()


def _past_iso(days: int = 365) -> str:
    return (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)).isoformat()


def _make_cert(
    cn: str = "www.example.com",
    issuer_cn: str = "Let's Encrypt Authority X3",
    issuer_org: str = "Let's Encrypt",
    sans: list[str] | None = None,
    self_signed: bool = False,
    not_before: str | None = None,
    not_after: str | None = None,
    serial: str = "ABC123",
) -> dict:
    return {
        "subject": {"commonName": cn},
        "issuer": {
            "commonName": issuer_cn if not self_signed else cn,
            "organizationName": issuer_org if not self_signed else "",
        },
        "sans": sans or [cn],
        "not_before": not_before or _past_iso(),
        "not_after": not_after or _future_iso(),
        "self_signed": self_signed,
        "serial": serial,
        "version": 3,
        "protocols": [],
    }


# ---------------------------------------------------------------------------
# Metadata / init
# ---------------------------------------------------------------------------


class TestTlsAnalysisCheckInit:
    """Test TlsAnalysisCheck metadata and initialization."""

    def test_check_metadata(self):
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        assert check.name == "tls_analysis"
        assert "TLS" in check.description or "tls" in check.description.lower()

    def test_conditions(self):
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "services"
        assert check.conditions[0].operator == "truthy"

    def test_produces(self):
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        assert "tls_data" in check.produces
        assert "tls_hosts" in check.produces

    def test_references(self):
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        assert len(check.references) > 0
        assert any("OWASP" in r or "CWE" in r for r in check.references)

    def test_tls_ports(self):
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        assert 443 in check.TLS_PORTS
        assert 8443 in check.TLS_PORTS


# ---------------------------------------------------------------------------
# Pure helpers — tested directly (no mocking needed)
# ---------------------------------------------------------------------------


class TestTlsHelpers:
    """Test _parse_dn and _parse_cert_date without mocking."""

    def test_parse_dn(self):
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        dn = (
            (("commonName", "example.com"),),
            (("organizationName", "Example Inc"),),
        )
        parsed = check._parse_dn(dn)
        assert parsed["commonName"] == "example.com"
        assert parsed["organizationName"] == "Example Inc"

    def test_parse_cert_date_valid(self):
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        result = check._parse_cert_date("Mar 10 12:00:00 2025 GMT")
        assert "2025-03-10" in result

    def test_parse_cert_date_invalid_passthrough(self):
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        result = check._parse_cert_date("not-a-date")
        assert result == "not-a-date"


# ---------------------------------------------------------------------------
# Run-level behaviour
# Mock rationale: _get_cert_info wraps ssl.create_default_context +
# socket.create_connection + wrap_socket + getpeercert. _probe_protocols
# tries multiple SSLContext protocol constants with separate TCP connections.
# Reproducing the full SSL handshake in a unit test is impractical.
# ---------------------------------------------------------------------------


class TestTlsAnalysisCheckRun:
    """Test TlsAnalysisCheck runtime behavior."""

    @pytest.mark.asyncio
    async def test_no_services_fails_with_error_message(self):
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        result = await check.run({"services": []})
        assert result.success is False
        assert any("services" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_no_tls_services_empty_output(self):
        """Non-TLS services on non-TLS ports produce empty output."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        svc = Service(
            url="http://db.example.com:6379", host="db.example.com", port=6379, scheme="http"
        )
        result = await check.run({"services": [svc]})
        assert result.outputs["tls_data"] == {}
        assert result.outputs["tls_hosts"] == []

    @pytest.mark.asyncio
    async def test_cert_observations_title_issuer_and_sans(self):
        """Verify certificate summary and SAN observations with specific titles."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        svc = Service(
            url="https://www.example.com:443", host="www.example.com", port=443, scheme="https"
        )
        cert = _make_cert(
            sans=["www.example.com", "api.example.com", "staging.example.com"],
        )

        with patch.object(check, "_get_cert_info", return_value=cert):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2", "TLS 1.3"]):
                result = await check.run({"services": [svc], "base_domain": "example.com"})

        assert result.targets_checked == 1

        # Certificate summary observation
        cert_obs = [f for f in result.observations if "TLS certificate" in f.title]
        assert len(cert_obs) == 1
        assert cert_obs[0].severity == "info"
        assert "Let's Encrypt" in cert_obs[0].title
        assert "www.example.com:443" in cert_obs[0].title

        # SANs discovery observation
        san_obs = [f for f in result.observations if "SANs discovered" in f.title]
        assert len(san_obs) == 1
        assert san_obs[0].severity == "info"
        assert "api.example.com" in san_obs[0].evidence

        # tls_hosts should contain new SANs, excluding the host itself
        tls_hosts = result.outputs["tls_hosts"]
        assert "api.example.com" in tls_hosts
        assert "staging.example.com" in tls_hosts
        assert "www.example.com" not in tls_hosts

    @pytest.mark.asyncio
    async def test_self_signed_certificate_observation(self):
        """Self-signed cert produces a medium-severity observation with specific title."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        svc = Service(
            url="https://dev.example.com:8443", host="dev.example.com", port=8443, scheme="https"
        )
        cert = _make_cert(cn="dev.example.com", self_signed=True)

        with patch.object(check, "_get_cert_info", return_value=cert):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                result = await check.run({"services": [svc], "base_domain": "example.com"})

        self_signed_obs = [f for f in result.observations if "self-signed" in f.title.lower()]
        assert len(self_signed_obs) == 1
        assert self_signed_obs[0].severity == "medium"
        assert "dev.example.com:8443" in self_signed_obs[0].title
        assert "dev.example.com" in self_signed_obs[0].evidence

    @pytest.mark.asyncio
    async def test_expired_certificate_observation(self):
        """Expired cert produces a medium-severity observation with 'expired' in title."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        svc = Service(
            url="https://old.example.com:443", host="old.example.com", port=443, scheme="https"
        )
        cert = _make_cert(
            cn="old.example.com",
            not_before=_past_iso(730),
            not_after=_past_iso(30),  # expired 30 days ago
        )

        with patch.object(check, "_get_cert_info", return_value=cert):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                result = await check.run({"services": [svc], "base_domain": "example.com"})

        expired_obs = [f for f in result.observations if "expired" in f.title.lower()]
        assert len(expired_obs) == 1
        assert expired_obs[0].severity == "medium"
        assert "old.example.com:443" in expired_obs[0].title

    @pytest.mark.asyncio
    async def test_expiring_soon_certificate_observation(self):
        """Cert expiring within 30 days produces a low-severity 'expires soon' observation."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        svc = Service(
            url="https://app.example.com:443", host="app.example.com", port=443, scheme="https"
        )
        cert = _make_cert(
            cn="app.example.com",
            not_before=_past_iso(350),
            not_after=_future_iso(15),  # 15 days left
        )

        with patch.object(check, "_get_cert_info", return_value=cert):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                result = await check.run({"services": [svc], "base_domain": "example.com"})

        expiring_obs = [f for f in result.observations if "expires soon" in f.title.lower()]
        assert len(expiring_obs) == 1
        assert expiring_obs[0].severity == "low"
        assert "app.example.com:443" in expiring_obs[0].title
        assert "days remaining" in expiring_obs[0].evidence

    @pytest.mark.asyncio
    async def test_deprecated_tls_protocol_observations(self):
        """Deprecated TLS 1.0 and 1.1 each produce a separate low-severity observation."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        svc = Service(
            url="https://legacy.example.com:443",
            host="legacy.example.com",
            port=443,
            scheme="https",
        )
        cert = _make_cert(cn="legacy.example.com")

        with patch.object(check, "_get_cert_info", return_value=cert):
            with patch.object(
                check, "_probe_protocols", return_value=["TLS 1.0", "TLS 1.1", "TLS 1.2"]
            ):
                result = await check.run({"services": [svc], "base_domain": "example.com"})

        deprecated_obs = [
            f for f in result.observations if "TLS 1.0" in f.title or "TLS 1.1" in f.title
        ]
        assert len(deprecated_obs) == 2
        assert all(f.severity == "low" for f in deprecated_obs)
        # Each should mention the specific protocol in the title
        titles = {f.title for f in deprecated_obs}
        assert any("TLS 1.0" in t for t in titles)
        assert any("TLS 1.1" in t for t in titles)

    @pytest.mark.asyncio
    async def test_tls_connect_failure_produces_empty_output(self):
        """If TLS connection fails (_get_cert_info returns None), endpoint is skipped."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        svc = Service(
            url="https://unreachable.example.com:443",
            host="unreachable.example.com",
            port=443,
            scheme="https",
        )

        with patch.object(check, "_get_cert_info", return_value=None):
            result = await check.run({"services": [svc], "base_domain": "example.com"})

        assert result.outputs["tls_data"] == {}
        assert result.targets_checked == 0
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_wildcard_sans_excluded_from_hosts(self):
        """Wildcard SANs (*.example.com) must not appear in tls_hosts."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        svc = Service(
            url="https://www.example.com:443", host="www.example.com", port=443, scheme="https"
        )
        cert = _make_cert(
            sans=["www.example.com", "*.example.com", "*.dev.example.com", "api.example.com"],
        )

        with patch.object(check, "_get_cert_info", return_value=cert):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                result = await check.run({"services": [svc], "base_domain": "example.com"})

        tls_hosts = result.outputs["tls_hosts"]
        assert "api.example.com" in tls_hosts
        assert "*.example.com" not in tls_hosts
        assert "*.dev.example.com" not in tls_hosts
        assert "www.example.com" not in tls_hosts

    @pytest.mark.asyncio
    async def test_multiple_services_deduplication(self):
        """Same host:port should only be checked once even with duplicate services."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()

        svc1 = Service(
            url="https://www.example.com:443", host="www.example.com", port=443, scheme="https"
        )
        svc2 = Service(
            url="https://www.example.com:443", host="www.example.com", port=443, scheme="https"
        )
        cert = _make_cert()
        call_count = 0

        async def counting_get_cert_info(host, port):
            nonlocal call_count
            call_count += 1
            return cert

        with patch.object(check, "_get_cert_info", side_effect=counting_get_cert_info):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                result = await check.run({"services": [svc1, svc2], "base_domain": "example.com"})

        assert call_count == 1
        assert result.targets_checked == 1

    @pytest.mark.asyncio
    async def test_non_https_on_tls_port_is_checked(self):
        """Services on known TLS ports are checked even if scheme is http."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        svc = Service(
            url="http://www.example.com:443", host="www.example.com", port=443, scheme="http"
        )
        cert = _make_cert()

        with patch.object(check, "_get_cert_info", return_value=cert):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                result = await check.run({"services": [svc], "base_domain": "example.com"})

        # Should have checked — endpoint appears in tls_data
        assert "www.example.com:443" in result.outputs["tls_data"]
        assert result.targets_checked == 1
