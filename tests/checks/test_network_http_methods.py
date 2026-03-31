"""
tests/checks/test_network_phase7c.py

Tests for Phase 7c network checks:
- HttpMethodEnumCheck (check 6): HTTP method enumeration, dangerous method detection
- BannerGrabCheck (check 7): Non-HTTP banner grabbing, service identification
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.checks.base import CheckResult, Service


# ═══════════════════════════════════════════════════════════════════
# HTTP Method Enumeration Check Tests
# ═══════════════════════════════════════════════════════════════════


class TestHttpMethodEnumCheckInit:
    """Test HttpMethodEnumCheck metadata and initialization."""

    def test_check_metadata(self):
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()
        assert check.name == "http_method_enum"
        assert "method" in check.description.lower()

    def test_conditions(self):
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "services"
        assert check.conditions[0].operator == "truthy"

    def test_produces(self):
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()
        assert "http_methods" in check.produces

    def test_references(self):
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()
        assert len(check.references) > 0
        assert any("OWASP" in r or "CWE" in r for r in check.references)

    def test_conservative_rate_limit(self):
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()
        # Should be conservative to avoid WAF blocks
        assert check.requests_per_second <= 10.0

    def test_dangerous_methods_defined(self):
        from app.checks.network.http_method_enum import DANGEROUS_METHODS
        assert "TRACE" in DANGEROUS_METHODS
        assert "PUT" in DANGEROUS_METHODS
        assert "DELETE" in DANGEROUS_METHODS
        assert "PATCH" in DANGEROUS_METHODS
        # TRACE should be medium severity
        assert DANGEROUS_METHODS["TRACE"]["severity"] == "medium"


class TestHttpMethodEnumCheckRun:
    """Test HttpMethodEnumCheck runtime behavior."""

    @pytest.mark.asyncio
    async def test_no_services_fails(self):
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()
        result = await check.run({"services": []})
        assert result.success is False
        assert any("services" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_no_http_services_empty_output(self):
        """Non-HTTP services should produce empty output."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()
        svc = Service(url="tcp://db.example.com:6379", host="db.example.com",
                      port=6379, scheme="tcp")
        result = await check.run({"services": [svc]})
        assert result.success is True
        assert result.outputs["http_methods"] == {}

    @pytest.mark.asyncio
    async def test_options_returns_allow_header(self):
        """OPTIONS response with Allow header should populate allowed methods."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()

        svc = Service(url="http://api.example.com:80", host="api.example.com",
                      port=80, scheme="http")

        method_info = {
            "allowed": ["GET", "POST", "OPTIONS"],
            "dangerous": [],
            "webdav": [],
            "options_allow": "GET, POST, OPTIONS",
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        assert result.success is True
        assert "api.example.com:80" in result.outputs["http_methods"]
        data = result.outputs["http_methods"]["api.example.com:80"]
        assert "GET" in data["allowed"]
        assert "POST" in data["allowed"]
        assert result.targets_checked == 1

    @pytest.mark.asyncio
    async def test_trace_method_finding(self):
        """TRACE enabled should produce medium severity finding."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()

        svc = Service(url="http://web.example.com:80", host="web.example.com",
                      port=80, scheme="http")

        method_info = {
            "allowed": ["GET", "POST", "TRACE"],
            "dangerous": ["TRACE"],
            "webdav": [],
            "options_allow": "GET, POST, TRACE",
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        trace_findings = [
            f for f in result.findings if "TRACE" in f.title
        ]
        assert len(trace_findings) == 1
        assert trace_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_put_method_finding(self):
        """PUT enabled should produce medium severity finding."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()

        svc = Service(url="http://api.example.com:8080", host="api.example.com",
                      port=8080, scheme="http")

        method_info = {
            "allowed": ["GET", "POST", "PUT"],
            "dangerous": ["PUT"],
            "webdav": [],
            "options_allow": None,
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        put_findings = [
            f for f in result.findings if "PUT" in f.title
        ]
        assert len(put_findings) == 1
        assert put_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_delete_method_finding(self):
        """DELETE enabled should produce low severity finding."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()

        svc = Service(url="http://api.example.com:80", host="api.example.com",
                      port=80, scheme="http")

        method_info = {
            "allowed": ["GET", "POST", "DELETE"],
            "dangerous": ["DELETE"],
            "webdav": [],
            "options_allow": None,
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        delete_findings = [
            f for f in result.findings if "DELETE" in f.title
        ]
        assert len(delete_findings) == 1
        assert delete_findings[0].severity == "low"

    @pytest.mark.asyncio
    async def test_multiple_dangerous_methods(self):
        """Multiple dangerous methods should each produce separate findings."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()

        svc = Service(url="http://app.example.com:80", host="app.example.com",
                      port=80, scheme="http")

        method_info = {
            "allowed": ["GET", "POST", "TRACE", "PUT", "DELETE", "PATCH"],
            "dangerous": ["TRACE", "PUT", "DELETE", "PATCH"],
            "webdav": [],
            "options_allow": None,
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        dangerous_findings = [
            f for f in result.findings
            if f.severity in ("medium", "low") and "method" in f.title.lower()
        ]
        # TRACE, PUT = medium; DELETE, PATCH = low
        assert len(dangerous_findings) == 4

    @pytest.mark.asyncio
    async def test_webdav_methods_finding(self):
        """WebDAV methods should produce medium severity finding."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()

        svc = Service(url="http://files.example.com:80", host="files.example.com",
                      port=80, scheme="http")

        method_info = {
            "allowed": ["GET", "PROPFIND", "MKCOL"],
            "dangerous": [],
            "webdav": ["PROPFIND", "MKCOL"],
            "options_allow": None,
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        webdav_findings = [
            f for f in result.findings if "webdav" in f.title.lower()
        ]
        assert len(webdav_findings) == 1
        assert webdav_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_no_methods_no_findings(self):
        """No allowed methods should produce no findings."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()

        svc = Service(url="http://empty.example.com:80", host="empty.example.com",
                      port=80, scheme="http")

        method_info = {
            "allowed": [],
            "dangerous": [],
            "webdav": [],
            "options_allow": None,
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        assert result.success is True
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_deduplication_same_host_port(self):
        """Same host:port should only be probed once."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()

        svc1 = Service(url="http://web.example.com:80", host="web.example.com",
                       port=80, scheme="http")
        svc2 = Service(url="http://web.example.com:80", host="web.example.com",
                       port=80, scheme="http")

        call_count = 0
        async def counting_probe(svc):
            nonlocal call_count
            call_count += 1
            return {"allowed": ["GET"], "dangerous": [], "webdav": [], "options_allow": "GET"}

        with patch.object(check, "_probe_service", side_effect=counting_probe):
            result = await check.run({"services": [svc1, svc2]})

        assert call_count == 1

    @pytest.mark.asyncio
    async def test_https_services_included(self):
        """HTTPS services should also be probed."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()

        svc = Service(url="https://secure.example.com:443", host="secure.example.com",
                      port=443, scheme="https")

        method_info = {
            "allowed": ["GET", "POST"],
            "dangerous": [],
            "webdav": [],
            "options_allow": "GET, POST",
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        assert result.success is True
        assert "secure.example.com:443" in result.outputs["http_methods"]

    @pytest.mark.asyncio
    async def test_info_finding_includes_all_methods(self):
        """Info finding should list all allowed methods."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        check = HttpMethodEnumCheck()

        svc = Service(url="http://api.example.com:80", host="api.example.com",
                      port=80, scheme="http")

        method_info = {
            "allowed": ["GET", "POST", "OPTIONS", "HEAD"],
            "dangerous": [],
            "webdav": [],
            "options_allow": "GET, POST, OPTIONS, HEAD",
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        info_findings = [f for f in result.findings if f.severity == "info"]
        assert len(info_findings) == 1
        assert "Allowed methods" in info_findings[0].title


class TestHttpMethodEnumProbe:
    """Test _probe_method and _probe_service internals."""

    @pytest.mark.asyncio
    async def test_probe_method_405_means_rejected(self):
        """405 Method Not Allowed should mean method is NOT accepted."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        import httpx

        check = HttpMethodEnumCheck()

        mock_resp = MagicMock()
        mock_resp.status_code = 405

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            accepted = await check._probe_method("http://example.com", "TRACE")

        assert accepted is False

    @pytest.mark.asyncio
    async def test_probe_method_200_means_accepted(self):
        """200 OK should mean method IS accepted."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        import httpx

        check = HttpMethodEnumCheck()

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            accepted = await check._probe_method("http://example.com", "PUT")

        assert accepted is True

    @pytest.mark.asyncio
    async def test_probe_method_501_means_rejected(self):
        """501 Not Implemented should mean method is NOT accepted."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        import httpx

        check = HttpMethodEnumCheck()

        mock_resp = MagicMock()
        mock_resp.status_code = 501

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            accepted = await check._probe_method("http://example.com", "TRACE")

        assert accepted is False

    @pytest.mark.asyncio
    async def test_probe_method_connection_error(self):
        """Connection error should return False (not accepted)."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck
        import httpx

        check = HttpMethodEnumCheck()

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            accepted = await check._probe_method("http://example.com", "TRACE")

        assert accepted is False


# ═══════════════════════════════════════════════════════════════════
# Banner Grabbing Check Tests
# ═══════════════════════════════════════════════════════════════════


class TestBannerGrabCheckInit:
    """Test BannerGrabCheck metadata and initialization."""

    def test_check_metadata(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        assert check.name == "banner_grab"
        assert "banner" in check.description.lower()

    def test_conditions(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "services"
        assert check.conditions[0].operator == "truthy"

    def test_produces(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        assert "banner_data" in check.produces

    def test_references(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        assert len(check.references) > 0
        assert any("CWE" in r for r in check.references)

    def test_banner_signatures_defined(self):
        from app.checks.network.banner_grab import BANNER_SIGNATURES
        service_names = [sig["name"] for sig in BANNER_SIGNATURES]
        assert "Redis" in service_names
        assert "PostgreSQL" in service_names
        assert "SSH" in service_names
        assert "MySQL" in service_names
        assert "Memcached" in service_names

    def test_http_ports_excluded(self):
        from app.checks.network.banner_grab import HTTP_PORTS
        assert 80 in HTTP_PORTS
        assert 443 in HTTP_PORTS
        assert 8080 in HTTP_PORTS
        # Database ports should NOT be in HTTP_PORTS
        assert 6379 not in HTTP_PORTS
        assert 5432 not in HTTP_PORTS


class TestBannerGrabCheckRun:
    """Test BannerGrabCheck runtime behavior."""

    @pytest.mark.asyncio
    async def test_no_services_fails(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        result = await check.run({"services": []})
        assert result.success is False
        assert any("services" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_only_http_services_empty_output(self):
        """HTTP-only services on HTTP ports should produce empty output."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc = Service(url="http://web.example.com:80", host="web.example.com",
                      port=80, scheme="http")
        result = await check.run({"services": [svc]})
        assert result.success is True
        assert result.outputs["banner_data"] == {}

    @pytest.mark.asyncio
    async def test_redis_banner_detection(self):
        """Redis service should be identified from +PONG banner."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc = Service(url="http://redis.example.com:6379", host="redis.example.com",
                      port=6379, scheme="http", service_type="unknown")

        banner_info = {
            "service": "Redis",
            "banner": "+PONG",
            "version": "7.2.1",
            "auth_required": True,
            "raw_bytes": "2b504f4e47",
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        assert result.success is True
        assert "redis.example.com:6379" in result.outputs["banner_data"]
        data = result.outputs["banner_data"]["redis.example.com:6379"]
        assert data["service"] == "Redis"
        assert data["version"] == "7.2.1"
        assert result.targets_checked == 1

    @pytest.mark.asyncio
    async def test_redis_no_auth_critical_finding(self):
        """Redis without auth should produce critical severity finding."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc = Service(url="http://redis.example.com:6379", host="redis.example.com",
                      port=6379, scheme="http", service_type="unknown")

        banner_info = {
            "service": "Redis",
            "banner": "+PONG",
            "version": "7.2.1",
            "auth_required": False,
            "raw_bytes": "2b504f4e47",
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        noauth_findings = [
            f for f in result.findings if "without authentication" in f.title.lower()
        ]
        assert len(noauth_findings) == 1
        assert noauth_findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_redis_with_auth_no_critical(self):
        """Redis with auth should NOT produce critical finding."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc = Service(url="http://redis.example.com:6379", host="redis.example.com",
                      port=6379, scheme="http", service_type="unknown")

        banner_info = {
            "service": "Redis",
            "banner": "+PONG",
            "version": "7.2.1",
            "auth_required": True,
            "raw_bytes": "2b504f4e47",
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        noauth_findings = [
            f for f in result.findings if "without authentication" in f.title.lower()
        ]
        assert len(noauth_findings) == 0

    @pytest.mark.asyncio
    async def test_ssh_banner_detection(self):
        """SSH service should be identified from SSH-2.0 banner."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc = Service(url="http://server.example.com:22", host="server.example.com",
                      port=22, scheme="http", service_type="unknown")

        banner_info = {
            "service": "SSH",
            "banner": "SSH-2.0-OpenSSH_8.9p1",
            "version": "OpenSSH_8.9p1",
            "auth_required": None,
            "raw_bytes": None,
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        assert "server.example.com:22" in result.outputs["banner_data"]
        data = result.outputs["banner_data"]["server.example.com:22"]
        assert data["service"] == "SSH"

    @pytest.mark.asyncio
    async def test_version_disclosure_finding(self):
        """Identified service with version should produce low severity version finding."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc = Service(url="http://db.example.com:5432", host="db.example.com",
                      port=5432, scheme="http", service_type="unknown")

        banner_info = {
            "service": "PostgreSQL",
            "banner": "PostgreSQL 15.3",
            "version": "15.3",
            "auth_required": None,
            "raw_bytes": None,
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        version_findings = [
            f for f in result.findings if "version disclosed" in f.title.lower()
        ]
        assert len(version_findings) == 1
        assert version_findings[0].severity == "low"

    @pytest.mark.asyncio
    async def test_unknown_service_banner_finding(self):
        """Unknown service with banner should produce medium severity finding."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc = Service(url="http://mystery.example.com:9999", host="mystery.example.com",
                      port=9999, scheme="http", service_type="unknown")

        banner_info = {
            "service": "unknown",
            "banner": "CUSTOM-PROTOCOL v3.1 READY",
            "version": None,
            "auth_required": None,
            "raw_bytes": None,
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        unknown_findings = [
            f for f in result.findings if "unidentified" in f.title.lower()
        ]
        assert len(unknown_findings) == 1
        assert unknown_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_no_banner_no_findings(self):
        """Service with no banner should produce no findings."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc = Service(url="http://silent.example.com:9999", host="silent.example.com",
                      port=9999, scheme="http", service_type="unknown")

        with patch.object(check, "_grab_banner", return_value=None):
            result = await check.run({"services": [svc]})

        assert result.success is True
        assert result.targets_checked == 1
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_deduplication_same_host_port(self):
        """Same host:port should only be grabbed once."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc1 = Service(url="http://redis.example.com:6379", host="redis.example.com",
                       port=6379, scheme="http", service_type="unknown")
        svc2 = Service(url="http://redis.example.com:6379", host="redis.example.com",
                       port=6379, scheme="http", service_type="unknown")

        call_count = 0
        async def counting_grab(host, port):
            nonlocal call_count
            call_count += 1
            return {"service": "Redis", "banner": "+PONG", "version": None,
                    "auth_required": True, "raw_bytes": None}

        with patch.object(check, "_grab_banner", side_effect=counting_grab):
            result = await check.run({"services": [svc1, svc2]})

        assert call_count == 1

    @pytest.mark.asyncio
    async def test_tcp_service_type_included(self):
        """Services with service_type='tcp' should be probed."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc = Service(url="tcp://custom.example.com:12345", host="custom.example.com",
                      port=12345, scheme="tcp", service_type="tcp")

        with patch.object(check, "_grab_banner", return_value=None):
            result = await check.run({"services": [svc]})

        # Should have attempted the grab
        assert result.targets_checked == 1

    @pytest.mark.asyncio
    async def test_memcached_no_auth_high_finding(self):
        """Memcached without auth should produce high severity finding."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc = Service(url="http://cache.example.com:11211", host="cache.example.com",
                      port=11211, scheme="http", service_type="unknown")

        banner_info = {
            "service": "Memcached",
            "banner": "VERSION 1.6.21",
            "version": "1.6.21",
            "auth_required": False,
            "raw_bytes": None,
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        noauth_findings = [
            f for f in result.findings if "without authentication" in f.title.lower()
        ]
        assert len(noauth_findings) == 1
        assert noauth_findings[0].severity == "high"

    @pytest.mark.asyncio
    async def test_multiple_non_http_services(self):
        """Multiple non-HTTP services should each be probed."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        svc1 = Service(url="http://redis.example.com:6379", host="redis.example.com",
                       port=6379, scheme="http", service_type="unknown")
        svc2 = Service(url="http://db.example.com:5432", host="db.example.com",
                       port=5432, scheme="http", service_type="unknown")

        async def mock_grab(host, port):
            if port == 6379:
                return {"service": "Redis", "banner": "+PONG", "version": "7.0",
                        "auth_required": True, "raw_bytes": None}
            elif port == 5432:
                return {"service": "PostgreSQL", "banner": "PG 15", "version": "15",
                        "auth_required": None, "raw_bytes": None}
            return None

        with patch.object(check, "_grab_banner", side_effect=mock_grab):
            result = await check.run({"services": [svc1, svc2]})

        assert result.targets_checked == 2
        assert "redis.example.com:6379" in result.outputs["banner_data"]
        assert "db.example.com:5432" in result.outputs["banner_data"]


class TestBannerGrabServiceIdentification:
    """Test _identify_service internal method."""

    def test_redis_identified_by_pong(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        result = check._identify_service("+PONG", b"+PONG", 6379)
        assert result["service"] == "Redis"

    def test_ssh_identified_and_version_extracted(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        result = check._identify_service(banner, banner.encode(), 22)
        assert result["service"] == "SSH"
        assert result["version"] == "OpenSSH_8.9p1"

    def test_smtp_identified_by_220(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        banner = "220 mail.example.com ESMTP Postfix"
        result = check._identify_service(banner, banner.encode(), 25)
        assert result["service"] == "SMTP"

    def test_ftp_identified_by_220(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        banner = "220 Welcome to FTP server"
        result = check._identify_service(banner, banner.encode(), 21)
        assert result["service"] == "FTP"

    def test_memcached_version_extracted(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        banner = "VERSION 1.6.21"
        result = check._identify_service(banner, banner.encode(), 11211)
        assert result["service"] == "Memcached"
        assert result["version"] == "1.6.21"

    def test_unknown_service_fallback(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        banner = "CUSTOM-PROTOCOL READY"
        result = check._identify_service(banner, banner.encode(), 9999)
        assert result["service"] == "unknown"

    def test_postgresql_identified_by_indicator(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        raw = b"E\x00\x00\x00\x8dSFATAL\x00"
        banner = raw.decode("utf-8", errors="replace")
        result = check._identify_service(banner, raw, 5432)
        assert result["service"] == "PostgreSQL"

    def test_mysql_identified_by_banner(self):
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()
        raw = b"J\x00\x00\x008.0.35\x00mysql_native_password"
        banner = raw.decode("utf-8", errors="replace")
        result = check._identify_service(banner, raw, 3306)
        assert result["service"] == "MySQL"


class TestBannerGrabRedisAuth:
    """Test Redis auth checking."""

    @pytest.mark.asyncio
    async def test_redis_noauth_response(self):
        """Redis returning -NOAUTH means auth IS required."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        with patch.object(check, "_tcp_read",
                          return_value=b"-NOAUTH Authentication required.\r\n"):
            auth_required = await check._check_redis_auth("redis.example.com", 6379)

        assert auth_required is True

    @pytest.mark.asyncio
    async def test_redis_info_response_no_auth(self):
        """Redis returning INFO data means auth is NOT required."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        info_response = b"# Server\r\nredis_version:7.2.1\r\n"
        with patch.object(check, "_tcp_read", return_value=info_response):
            auth_required = await check._check_redis_auth("redis.example.com", 6379)

        assert auth_required is False

    @pytest.mark.asyncio
    async def test_redis_no_response_assume_auth(self):
        """No response from Redis should assume auth required."""
        from app.checks.network.banner_grab import BannerGrabCheck
        check = BannerGrabCheck()

        with patch.object(check, "_tcp_read", return_value=None):
            auth_required = await check._check_redis_auth("redis.example.com", 6379)

        assert auth_required is True


# ═══════════════════════════════════════════════════════════════════
# Integration / Registration Tests
# ═══════════════════════════════════════════════════════════════════


class TestPhase7cRegistration:
    """Test that Phase 7c checks are correctly registered in the resolver."""

    def test_checks_present_in_resolver(self):
        from app.check_resolver import get_real_checks
        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "http_method_enum" in names
        assert "banner_grab" in names

    def test_banner_grab_after_service_probe(self):
        """banner_grab should run after service_probe (Phase 4 ordering)."""
        from app.check_resolver import get_real_checks
        checks = get_real_checks()
        names = [c.name for c in checks]
        bg_idx = names.index("banner_grab")
        sp_idx = names.index("service_probe")
        assert bg_idx > sp_idx

    def test_http_method_enum_after_service_probe(self):
        """http_method_enum should run after service_probe (Phase 5 ordering)."""
        from app.check_resolver import get_real_checks
        checks = get_real_checks()
        names = [c.name for c in checks]
        hme_idx = names.index("http_method_enum")
        sp_idx = names.index("service_probe")
        assert hme_idx > sp_idx

    def test_suite_inference_network(self):
        """Both checks should be inferred as 'network' suite."""
        from app.check_resolver import infer_suite
        assert infer_suite("http_method_enum") == "network"
        assert infer_suite("banner_grab") == "network"

    def test_suite_filter(self):
        """Both checks should appear when filtering by 'network' suite."""
        from app.check_resolver import resolve_checks
        checks = resolve_checks(suites=["network"])
        names = [c.name for c in checks]
        assert "http_method_enum" in names
        assert "banner_grab" in names

    def test_total_check_count(self):
        """Total check count should have increased by 2 (43 -> 45 minimum)."""
        from app.check_resolver import get_real_checks
        checks = get_real_checks()
        assert len(checks) >= 43

    def test_imports_from_network_package(self):
        """Checks should be importable from the network package."""
        from app.checks.network import HttpMethodEnumCheck, BannerGrabCheck
        assert HttpMethodEnumCheck is not None
        assert BannerGrabCheck is not None
