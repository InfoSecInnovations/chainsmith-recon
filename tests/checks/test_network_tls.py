"""Tests for TlsAnalysisCheck: TLS handshake, certificate, and cipher analysis."""

import datetime
from unittest.mock import patch

import pytest

from app.checks.base import Service


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


class TestTlsAnalysisCheckRun:
    """Test TlsAnalysisCheck runtime behavior."""

    @pytest.mark.asyncio
    async def test_no_services_fails(self):
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
        # Port 6379 is Redis, not TLS, and scheme is not https
        svc = Service(
            url="http://db.example.com:6379", host="db.example.com", port=6379, scheme="http"
        )
        result = await check.run({"services": [svc]})
        assert result.success is True
        assert result.outputs["tls_data"] == {}
        assert result.outputs["tls_hosts"] == []

    @pytest.mark.asyncio
    async def test_https_service_cert_inspection(self):
        """Successfully inspect certificate on an HTTPS service."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()

        svc = Service(
            url="https://www.example.com:443", host="www.example.com", port=443, scheme="https"
        )

        future_date = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
        past_date = (datetime.datetime.utcnow() - datetime.timedelta(days=365)).isoformat()

        mock_cert_info = {
            "subject": {"commonName": "www.example.com"},
            "issuer": {
                "commonName": "Let's Encrypt Authority X3",
                "organizationName": "Let's Encrypt",
            },
            "sans": ["www.example.com", "api.example.com", "staging.example.com"],
            "not_before": past_date,
            "not_after": future_date,
            "self_signed": False,
            "serial": "ABC123",
            "version": 3,
            "protocols": [],
        }

        with patch.object(check, "_get_cert_info", return_value=mock_cert_info):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2", "TLS 1.3"]):
                result = await check.run(
                    {
                        "services": [svc],
                        "base_domain": "example.com",
                    }
                )

        assert result.success is True
        assert "www.example.com:443" in result.outputs["tls_data"]
        assert result.targets_checked == 1

        # Should find SANs as new hosts (excluding www.example.com itself)
        tls_hosts = result.outputs["tls_hosts"]
        assert "api.example.com" in tls_hosts
        assert "staging.example.com" in tls_hosts
        assert "www.example.com" not in tls_hosts

        # Should have at least cert summary finding
        assert len(result.findings) >= 1
        assert any("TLS certificate" in f.title for f in result.findings)
        # SANs finding
        assert any("SANs discovered" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_self_signed_certificate(self):
        """Self-signed cert should produce medium severity finding."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()

        svc = Service(
            url="https://dev.example.com:8443", host="dev.example.com", port=8443, scheme="https"
        )

        future_date = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
        past_date = (datetime.datetime.utcnow() - datetime.timedelta(days=365)).isoformat()

        mock_cert_info = {
            "subject": {"commonName": "dev.example.com"},
            "issuer": {"commonName": "dev.example.com"},
            "sans": ["dev.example.com"],
            "not_before": past_date,
            "not_after": future_date,
            "self_signed": True,
            "serial": "DEF456",
            "version": 3,
            "protocols": [],
        }

        with patch.object(check, "_get_cert_info", return_value=mock_cert_info):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                result = await check.run(
                    {
                        "services": [svc],
                        "base_domain": "example.com",
                    }
                )

        assert result.success is True
        self_signed_findings = [f for f in result.findings if "self-signed" in f.title.lower()]
        assert len(self_signed_findings) == 1
        assert self_signed_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_expired_certificate(self):
        """Expired cert should produce medium severity finding."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()

        svc = Service(
            url="https://old.example.com:443", host="old.example.com", port=443, scheme="https"
        )

        expired_date = (datetime.datetime.utcnow() - datetime.timedelta(days=30)).isoformat()
        past_date = (datetime.datetime.utcnow() - datetime.timedelta(days=730)).isoformat()

        mock_cert_info = {
            "subject": {"commonName": "old.example.com"},
            "issuer": {"commonName": "DigiCert Inc"},
            "sans": ["old.example.com"],
            "not_before": past_date,
            "not_after": expired_date,
            "self_signed": False,
            "serial": "GHI789",
            "version": 3,
            "protocols": [],
        }

        with patch.object(check, "_get_cert_info", return_value=mock_cert_info):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                result = await check.run(
                    {
                        "services": [svc],
                        "base_domain": "example.com",
                    }
                )

        assert result.success is True
        expired_findings = [f for f in result.findings if "expired" in f.title.lower()]
        assert len(expired_findings) == 1
        assert expired_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_expiring_soon_certificate(self):
        """Cert expiring within 30 days should produce low severity finding."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()

        svc = Service(
            url="https://app.example.com:443", host="app.example.com", port=443, scheme="https"
        )

        soon_date = (datetime.datetime.utcnow() + datetime.timedelta(days=15)).isoformat()
        past_date = (datetime.datetime.utcnow() - datetime.timedelta(days=350)).isoformat()

        mock_cert_info = {
            "subject": {"commonName": "app.example.com"},
            "issuer": {"commonName": "DigiCert Inc"},
            "sans": ["app.example.com"],
            "not_before": past_date,
            "not_after": soon_date,
            "self_signed": False,
            "serial": "JKL012",
            "version": 3,
            "protocols": [],
        }

        with patch.object(check, "_get_cert_info", return_value=mock_cert_info):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                result = await check.run(
                    {
                        "services": [svc],
                        "base_domain": "example.com",
                    }
                )

        assert result.success is True
        expiring_findings = [f for f in result.findings if "expires soon" in f.title.lower()]
        assert len(expiring_findings) == 1
        assert expiring_findings[0].severity == "low"

    @pytest.mark.asyncio
    async def test_deprecated_tls_protocol(self):
        """Deprecated TLS versions should produce low severity findings."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()

        svc = Service(
            url="https://legacy.example.com:443",
            host="legacy.example.com",
            port=443,
            scheme="https",
        )

        future_date = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
        past_date = (datetime.datetime.utcnow() - datetime.timedelta(days=365)).isoformat()

        mock_cert_info = {
            "subject": {"commonName": "legacy.example.com"},
            "issuer": {"commonName": "DigiCert Inc"},
            "sans": ["legacy.example.com"],
            "not_before": past_date,
            "not_after": future_date,
            "self_signed": False,
            "serial": "MNO345",
            "version": 3,
            "protocols": [],
        }

        with patch.object(check, "_get_cert_info", return_value=mock_cert_info):
            with patch.object(
                check, "_probe_protocols", return_value=["TLS 1.0", "TLS 1.1", "TLS 1.2"]
            ):
                result = await check.run(
                    {
                        "services": [svc],
                        "base_domain": "example.com",
                    }
                )

        assert result.success is True
        deprecated_findings = [
            f for f in result.findings if "TLS 1.0" in f.title or "TLS 1.1" in f.title
        ]
        assert len(deprecated_findings) == 2
        assert all(f.severity == "low" for f in deprecated_findings)

    @pytest.mark.asyncio
    async def test_tls_connect_failure_skips(self):
        """If TLS connection fails, skip the endpoint gracefully."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()

        svc = Service(
            url="https://unreachable.example.com:443",
            host="unreachable.example.com",
            port=443,
            scheme="https",
        )

        with patch.object(check, "_get_cert_info", return_value=None):
            result = await check.run(
                {
                    "services": [svc],
                    "base_domain": "example.com",
                }
            )

        assert result.success is True
        assert result.outputs["tls_data"] == {}
        assert result.targets_checked == 0

    @pytest.mark.asyncio
    async def test_wildcard_sans_excluded_from_hosts(self):
        """Wildcard SANs (*.example.com) should not appear in tls_hosts."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()

        svc = Service(
            url="https://www.example.com:443", host="www.example.com", port=443, scheme="https"
        )

        future_date = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
        past_date = (datetime.datetime.utcnow() - datetime.timedelta(days=365)).isoformat()

        mock_cert_info = {
            "subject": {"commonName": "www.example.com"},
            "issuer": {"commonName": "DigiCert Inc"},
            "sans": ["www.example.com", "*.example.com", "*.dev.example.com", "api.example.com"],
            "not_before": past_date,
            "not_after": future_date,
            "self_signed": False,
            "serial": "PQR678",
            "version": 3,
            "protocols": [],
        }

        with patch.object(check, "_get_cert_info", return_value=mock_cert_info):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                result = await check.run(
                    {
                        "services": [svc],
                        "base_domain": "example.com",
                    }
                )

        tls_hosts = result.outputs["tls_hosts"]
        assert "api.example.com" in tls_hosts
        assert "*.example.com" not in tls_hosts
        assert "*.dev.example.com" not in tls_hosts
        assert "www.example.com" not in tls_hosts

    @pytest.mark.asyncio
    async def test_multiple_services_deduplication(self):
        """Same host:port should only be checked once."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()

        svc1 = Service(
            url="https://www.example.com:443", host="www.example.com", port=443, scheme="https"
        )
        svc2 = Service(
            url="https://www.example.com:443", host="www.example.com", port=443, scheme="https"
        )

        future_date = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
        past_date = (datetime.datetime.utcnow() - datetime.timedelta(days=365)).isoformat()

        mock_cert_info = {
            "subject": {"commonName": "www.example.com"},
            "issuer": {"commonName": "DigiCert Inc"},
            "sans": ["www.example.com"],
            "not_before": past_date,
            "not_after": future_date,
            "self_signed": False,
            "serial": "STU901",
            "version": 3,
            "protocols": [],
        }

        call_count = 0

        async def counting_get_cert_info(host, port):
            nonlocal call_count
            call_count += 1
            return mock_cert_info

        with patch.object(check, "_get_cert_info", side_effect=counting_get_cert_info):
            with patch.object(check, "_probe_protocols", return_value=["TLS 1.2"]):
                await check.run(
                    {
                        "services": [svc1, svc2],
                        "base_domain": "example.com",
                    }
                )

        assert call_count == 1  # Only checked once despite 2 services

    @pytest.mark.asyncio
    async def test_non_https_on_tls_port_checked(self):
        """Services on known TLS ports should be checked even if scheme is http."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()

        # Port 443 but marked as http (service_probe may not have run yet)
        svc = Service(
            url="http://www.example.com:443", host="www.example.com", port=443, scheme="http"
        )

        with patch.object(check, "_get_cert_info", return_value=None):
            with patch.object(check, "_probe_protocols", return_value=[]):
                result = await check.run(
                    {
                        "services": [svc],
                        "base_domain": "example.com",
                    }
                )

        # Should have attempted the check (even though it returned None)
        assert result.success is True

    def test_parse_dn(self):
        """Test distinguished name parsing."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        dn = (
            (("commonName", "example.com"),),
            (("organizationName", "Example Inc"),),
        )
        parsed = check._parse_dn(dn)
        assert parsed["commonName"] == "example.com"
        assert parsed["organizationName"] == "Example Inc"

    def test_parse_cert_date(self):
        """Test certificate date parsing."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        date_str = "Mar 10 12:00:00 2025 GMT"
        result = check._parse_cert_date(date_str)
        assert "2025-03-10" in result

    def test_parse_cert_date_invalid(self):
        """Invalid date string should be returned as-is."""
        from app.checks.network.tls_analysis import TlsAnalysisCheck

        check = TlsAnalysisCheck()
        result = check._parse_cert_date("not-a-date")
        assert result == "not-a-date"
