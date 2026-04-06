"""Tests for HSTSPreloadCheck and SRICheck."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.hsts_preload import HSTSPreloadCheck
from app.checks.web.sri_check import SRICheck
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def service():
    return Service(
        url="http://target.com:80", host="target.com", port=80, scheme="http", service_type="http"
    )


@pytest.fixture
def https_service():
    return Service(
        url="https://target.com:443",
        host="target.com",
        port=443,
        scheme="https",
        service_type="http",
    )


def resp(status_code=200, body="", headers=None, error=None, url="http://target.com:80"):
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


def mock_client_multi(response_map=None, default=None):
    """Mock client that returns different responses based on URL/method."""
    if default is None:
        default = resp(404)

    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock()

    def _lookup(method, url):
        if response_map:
            for (m, pattern), response in response_map.items():
                if m == method and pattern in url:
                    return response
        return default

    async def dispatch_get(url, **kwargs):
        return _lookup("GET", url)

    async def dispatch_post(url, **kwargs):
        return _lookup("POST", url)

    mock.get = AsyncMock(side_effect=dispatch_get)
    mock.post = AsyncMock(side_effect=dispatch_post)
    mock.head = AsyncMock(side_effect=lambda url, **kw: _lookup("HEAD", url))
    mock._request = AsyncMock(side_effect=lambda m, url, **kw: _lookup(m, url))

    return mock


# ═══════════════════════════════════════════════════════════════════════════════
# HSTSPreloadCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestHSTSPreloadCheck:
    def test_init(self):
        check = HSTSPreloadCheck()
        assert check.name == "hsts_preload"
        assert "hsts_preload_info" in check.produces

    @pytest.mark.asyncio
    async def test_preloaded_domain(self, https_service):
        """Domain found on preload list."""
        api_response = json.dumps({"status": "preloaded", "domain": "target.com"})
        hsts_header = "max-age=31536000; includeSubDomains; preload"

        client = mock_client_multi(
            response_map={
                ("GET", "hstspreload.org"): resp(200, body=api_response),
                ("GET", "target.com"): resp(
                    200, headers={"strict-transport-security": hsts_header}
                ),
            },
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, {})

        assert result.success
        assert result.outputs["hsts_preload_info"]["preloaded"] is True
        assert any("HSTS preloaded" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_not_preloaded_with_hsts(self, https_service):
        """HSTS header present but domain not preloaded."""
        api_response = json.dumps({"status": "unknown", "domain": "target.com"})
        hsts_header = "max-age=31536000; includeSubDomains"

        client = mock_client_multi(
            response_map={
                ("GET", "hstspreload.org"): resp(200, body=api_response),
                ("GET", "target.com"): resp(
                    200, headers={"strict-transport-security": hsts_header}
                ),
            },
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, {})

        assert result.outputs["hsts_preload_info"]["preloaded"] is False
        not_preloaded = [f for f in result.findings if "not preloaded" in f.title]
        assert len(not_preloaded) == 1
        assert not_preloaded[0].severity == "low"

    @pytest.mark.asyncio
    async def test_preload_directive_pending(self, https_service):
        """Has preload directive but not yet on the list."""
        api_response = json.dumps({"status": "pending", "domain": "target.com"})
        hsts_header = "max-age=31536000; includeSubDomains; preload"

        client = mock_client_multi(
            response_map={
                ("GET", "hstspreload.org"): resp(200, body=api_response),
                ("GET", "target.com"): resp(
                    200, headers={"strict-transport-security": hsts_header}
                ),
            },
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, {})

        assert any("not yet preloaded" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_no_hsts_header_http(self, service):
        """HTTP service with no HSTS — check not applicable."""
        client = mock_client_multi(default=resp(200, headers={}))
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(service, {})

        assert any("No HSTS" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_hsts_from_context(self, https_service):
        """HSTS header read from header_analysis context output."""
        api_response = json.dumps({"status": "preloaded"})
        context = {
            "header_info": {
                "headers": {
                    "strict-transport-security": "max-age=63072000; includeSubDomains; preload"
                },
            },
        }

        client = mock_client_multi(
            response_map={("GET", "hstspreload.org"): resp(200, body=api_response)},
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, context)

        assert result.outputs["hsts_preload_info"]["preloaded"] is True

    @pytest.mark.asyncio
    async def test_short_max_age_noted(self, https_service):
        """Short max-age is mentioned in not-preloaded finding."""
        api_response = json.dumps({"status": "unknown"})
        hsts_header = "max-age=86400"

        client = mock_client_multi(
            response_map={
                ("GET", "hstspreload.org"): resp(200, body=api_response),
                ("GET", "target.com"): resp(
                    200, headers={"strict-transport-security": hsts_header}
                ),
            },
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, {})

        not_preloaded = [f for f in result.findings if "not preloaded" in f.title]
        assert len(not_preloaded) == 1
        assert "max-age too short" in not_preloaded[0].description

    @pytest.mark.asyncio
    async def test_api_unreachable(self, https_service):
        """Graceful handling when hstspreload.org API is down."""
        hsts_header = "max-age=31536000; includeSubDomains; preload"
        client = mock_client_multi(
            response_map={
                ("GET", "hstspreload.org"): resp(500, error="Server Error"),
                ("GET", "target.com"): resp(
                    200, headers={"strict-transport-security": hsts_header}
                ),
            },
        )
        with patch("app.checks.web.hsts_preload.AsyncHttpClient", return_value=client):
            check = HSTSPreloadCheck()
            result = await check.check_service(https_service, {})

        assert result.success


# ═══════════════════════════════════════════════════════════════════════════════
# SRICheck
# ═══════════════════════════════════════════════════════════════════════════════


HTML_WITH_EXTERNAL_NO_SRI = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdn.example.com/bootstrap.css">
    <script src="https://cdn.example.com/app.js"></script>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="/static/local.js"></script>
</head>
<body>Hello</body>
</html>"""

HTML_WITH_SRI = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdn.example.com/bootstrap.css"
          integrity="sha384-abc123" crossorigin="anonymous">
    <script src="https://cdn.example.com/app.js"
            integrity="sha384-def456" crossorigin="anonymous"></script>
</head>
<body>Hello</body>
</html>"""

HTML_NO_EXTERNAL = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/static/style.css">
    <script src="/static/app.js"></script>
</head>
<body>Hello</body>
</html>"""

HTML_MIXED_SRI = """<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.example.com/jquery.js"
            integrity="sha384-xyz789" crossorigin="anonymous"></script>
    <script src="https://cdn.example.com/app.js"></script>
</head>
<body>Hello</body>
</html>"""


class TestSRICheck:
    def test_init(self):
        check = SRICheck()
        assert check.name == "sri_check"
        assert "sri_info" in check.produces

    @pytest.mark.asyncio
    async def test_external_without_sri(self, service):
        """External resources without SRI are flagged."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=HTML_WITH_EXTERNAL_NO_SRI, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.success
        # Should find 3 external resources without SRI (2 scripts + 1 stylesheet)
        assert result.outputs["sri_info"]["without_sri"] == 3
        assert result.outputs["sri_info"]["with_sri"] == 0
        # Summary finding
        summary = [f for f in result.findings if "external resource(s) without SRI" in f.title]
        assert len(summary) == 1

    @pytest.mark.asyncio
    async def test_all_sri_present(self, service):
        """All external resources have SRI — good finding."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=HTML_WITH_SRI, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.outputs["sri_info"]["with_sri"] == 2
        assert result.outputs["sri_info"]["without_sri"] == 0
        assert any("All external resources use SRI" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_no_external_resources(self, service):
        """No external resources — info finding."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=HTML_NO_EXTERNAL, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.outputs["sri_info"]["total_external"] == 0
        assert any("No external resources" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_mixed_sri(self, service):
        """Mix of SRI and non-SRI external resources."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=HTML_MIXED_SRI, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.outputs["sri_info"]["with_sri"] == 1
        assert result.outputs["sri_info"]["without_sri"] == 1

    @pytest.mark.asyncio
    async def test_severity_scales_with_count(self, service):
        """Medium severity when 3+ external resources lack SRI."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=HTML_WITH_EXTERNAL_NO_SRI, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        summary = [f for f in result.findings if "external resource(s) without SRI" in f.title]
        assert summary[0].severity == "medium"  # 3 resources = medium

    @pytest.mark.asyncio
    async def test_protocol_relative_url(self, service):
        """Protocol-relative URLs (//cdn.example.com) are treated as external."""
        html = '<html><head><script src="//cdn.example.com/lib.js"></script></head></html>'
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body=html, headers={"content-type": "text/html"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.outputs["sri_info"]["without_sri"] == 1

    @pytest.mark.asyncio
    async def test_non_html_response_skipped(self, service):
        """Non-HTML responses are not analyzed."""
        client = mock_client_multi(
            response_map={
                ("GET", "target.com:80/"): resp(
                    200, body='{"api": true}', headers={"content-type": "application/json"}
                ),
            },
            default=resp(404),
        )
        with patch("app.checks.web.sri_check.AsyncHttpClient", return_value=client):
            check = SRICheck()
            result = await check.check_service(service, {})

        assert result.outputs["sri_info"]["total_external"] == 0
