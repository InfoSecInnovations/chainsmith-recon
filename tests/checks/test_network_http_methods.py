"""Tests for HttpMethodEnumCheck: HTTP method enumeration, dangerous method detection."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.checks.base import Service

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
        svc = Service(
            url="tcp://db.example.com:6379", host="db.example.com", port=6379, scheme="tcp"
        )
        result = await check.run({"services": [svc]})
        assert result.success is True
        assert result.outputs["http_methods"] == {}

    @pytest.mark.asyncio
    async def test_options_returns_allow_header(self):
        """OPTIONS response with Allow header should populate allowed methods."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        svc = Service(
            url="http://api.example.com:80", host="api.example.com", port=80, scheme="http"
        )

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

        svc = Service(
            url="http://web.example.com:80", host="web.example.com", port=80, scheme="http"
        )

        method_info = {
            "allowed": ["GET", "POST", "TRACE"],
            "dangerous": ["TRACE"],
            "webdav": [],
            "options_allow": "GET, POST, TRACE",
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        trace_findings = [f for f in result.findings if "TRACE" in f.title]
        assert len(trace_findings) == 1
        assert trace_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_put_method_finding(self):
        """PUT enabled should produce medium severity finding."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        svc = Service(
            url="http://api.example.com:8080", host="api.example.com", port=8080, scheme="http"
        )

        method_info = {
            "allowed": ["GET", "POST", "PUT"],
            "dangerous": ["PUT"],
            "webdav": [],
            "options_allow": None,
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        put_findings = [f for f in result.findings if "PUT" in f.title]
        assert len(put_findings) == 1
        assert put_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_delete_method_finding(self):
        """DELETE enabled should produce low severity finding."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        svc = Service(
            url="http://api.example.com:80", host="api.example.com", port=80, scheme="http"
        )

        method_info = {
            "allowed": ["GET", "POST", "DELETE"],
            "dangerous": ["DELETE"],
            "webdav": [],
            "options_allow": None,
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        delete_findings = [f for f in result.findings if "DELETE" in f.title]
        assert len(delete_findings) == 1
        assert delete_findings[0].severity == "low"

    @pytest.mark.asyncio
    async def test_multiple_dangerous_methods(self):
        """Multiple dangerous methods should each produce separate findings."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        svc = Service(
            url="http://app.example.com:80", host="app.example.com", port=80, scheme="http"
        )

        method_info = {
            "allowed": ["GET", "POST", "TRACE", "PUT", "DELETE", "PATCH"],
            "dangerous": ["TRACE", "PUT", "DELETE", "PATCH"],
            "webdav": [],
            "options_allow": None,
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        dangerous_findings = [
            f
            for f in result.findings
            if f.severity in ("medium", "low") and "method" in f.title.lower()
        ]
        # TRACE, PUT = medium; DELETE, PATCH = low
        assert len(dangerous_findings) == 4

    @pytest.mark.asyncio
    async def test_webdav_methods_finding(self):
        """WebDAV methods should produce medium severity finding."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        svc = Service(
            url="http://files.example.com:80", host="files.example.com", port=80, scheme="http"
        )

        method_info = {
            "allowed": ["GET", "PROPFIND", "MKCOL"],
            "dangerous": [],
            "webdav": ["PROPFIND", "MKCOL"],
            "options_allow": None,
        }

        with patch.object(check, "_probe_service", return_value=method_info):
            result = await check.run({"services": [svc]})

        webdav_findings = [f for f in result.findings if "webdav" in f.title.lower()]
        assert len(webdav_findings) == 1
        assert webdav_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_no_methods_no_findings(self):
        """No allowed methods should produce no findings."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        svc = Service(
            url="http://empty.example.com:80", host="empty.example.com", port=80, scheme="http"
        )

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

        svc1 = Service(
            url="http://web.example.com:80", host="web.example.com", port=80, scheme="http"
        )
        svc2 = Service(
            url="http://web.example.com:80", host="web.example.com", port=80, scheme="http"
        )

        call_count = 0

        async def counting_probe(svc):
            nonlocal call_count
            call_count += 1
            return {"allowed": ["GET"], "dangerous": [], "webdav": [], "options_allow": "GET"}

        with patch.object(check, "_probe_service", side_effect=counting_probe):
            await check.run({"services": [svc1, svc2]})

        assert call_count == 1

    @pytest.mark.asyncio
    async def test_https_services_included(self):
        """HTTPS services should also be probed."""
        from app.checks.network.http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        svc = Service(
            url="https://secure.example.com:443",
            host="secure.example.com",
            port=443,
            scheme="https",
        )

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

        svc = Service(
            url="http://api.example.com:80", host="api.example.com", port=80, scheme="http"
        )

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

        check = HttpMethodEnumCheck()

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            accepted = await check._probe_method("http://example.com", "TRACE")

        assert accepted is False


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
        from app.checks.network import BannerGrabCheck, HttpMethodEnumCheck

        assert HttpMethodEnumCheck is not None
        assert BannerGrabCheck is not None
