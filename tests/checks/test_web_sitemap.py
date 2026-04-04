"""
Tests for Phase 6c content & structure discovery checks.

Covers:
- SitemapCheck (check 11)
- RedirectChainCheck (check 12)
- ErrorPageCheck (check 13)
- SSRFIndicatorCheck (check 14)

All HTTP calls are mocked to avoid actual network traffic.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.error_page import ErrorPageCheck
from app.checks.web.redirect_chain import RedirectChainCheck
from app.checks.web.sitemap import SitemapCheck
from app.checks.web.ssrf_indicator import SSRFIndicatorCheck
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
# SitemapCheck
# ═══════════════════════════════════════════════════════════════════════════════


SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://target.com/page1</loc></url>
  <url><loc>https://target.com/page2</loc></url>
  <url><loc>https://target.com/admin/dashboard</loc></url>
  <url><loc>https://target.com/api/v1/users</loc></url>
  <url><loc>https://target.com/api/v2/users</loc></url>
  <url><loc>https://target.com/internal/tools</loc></url>
</urlset>"""

SITEMAP_INDEX_XML = """<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://target.com/sitemap-main.xml</loc></sitemap>
  <sitemap><loc>https://target.com/sitemap-api.xml</loc></sitemap>
</sitemapindex>"""

SUB_SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://target.com/about</loc></url>
  <url><loc>https://target.com/staging/test</loc></url>
</urlset>"""


class TestSitemapCheck:
    def test_init(self):
        check = SitemapCheck()
        assert check.name == "sitemap"
        assert "sitemap_paths" in check.produces

    @pytest.mark.asyncio
    async def test_sitemap_from_robots(self, service):
        """Sitemap URL from robots.txt output is fetched and parsed."""
        check = SitemapCheck()
        context = {
            "robots_80": {
                "sitemaps": ["https://target.com/sitemap.xml"],
                "disallowed": [],
                "interesting": [],
            }
        }

        with patch(
            "app.checks.web.sitemap.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={("GET", "sitemap.xml"): resp(200, body=SITEMAP_XML)},
            ),
        ):
            result = await check.check_service(service, context)

        assert result.success
        assert len(result.findings) >= 1
        # Should find 6 paths
        info_findings = [f for f in result.findings if "sitemap-discovered" in (f.id or "")]
        assert len(info_findings) == 1
        assert "6" in info_findings[0].title

    @pytest.mark.asyncio
    async def test_sitemap_default_location(self, service):
        """Falls back to /sitemap.xml when robots.txt has no sitemaps."""
        check = SitemapCheck()
        context = {}

        with patch(
            "app.checks.web.sitemap.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={("GET", "sitemap.xml"): resp(200, body=SITEMAP_XML)},
            ),
        ):
            result = await check.check_service(service, context)

        assert result.success
        assert any("sitemap-discovered" in (f.id or "") for f in result.findings)

    @pytest.mark.asyncio
    async def test_sitemap_not_found(self, service):
        """No findings when sitemap returns 404."""
        check = SitemapCheck()
        context = {}

        with patch(
            "app.checks.web.sitemap.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, context)

        assert result.success
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_sensitive_paths_detected(self, service):
        """Sensitive paths (admin, internal) are flagged."""
        check = SitemapCheck()
        context = {}

        with patch(
            "app.checks.web.sitemap.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={("GET", "sitemap.xml"): resp(200, body=SITEMAP_XML)},
            ),
        ):
            result = await check.check_service(service, context)

        sensitive = [f for f in result.findings if "sensitive-paths" in (f.id or "")]
        assert len(sensitive) == 1

    @pytest.mark.asyncio
    async def test_api_versioning_detected(self, service):
        """Multiple API versions are flagged."""
        check = SitemapCheck()
        context = {}

        with patch(
            "app.checks.web.sitemap.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={("GET", "sitemap.xml"): resp(200, body=SITEMAP_XML)},
            ),
        ):
            result = await check.check_service(service, context)

        versioning = [f for f in result.findings if "api-versioning" in (f.id or "")]
        assert len(versioning) == 1
        assert "v1" in versioning[0].evidence
        assert "v2" in versioning[0].evidence

    @pytest.mark.asyncio
    async def test_sitemap_index(self, service):
        """Sitemap index files are followed to sub-sitemaps."""
        check = SitemapCheck()
        context = {}

        with patch(
            "app.checks.web.sitemap.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "/sitemap.xml"): resp(200, body=SITEMAP_INDEX_XML),
                    ("GET", "sitemap-main.xml"): resp(200, body=SUB_SITEMAP_XML),
                    ("GET", "sitemap-api.xml"): resp(200, body=SUB_SITEMAP_XML),
                },
            ),
        ):
            result = await check.check_service(service, context)

        assert result.success
        assert any("sitemap-discovered" in (f.id or "") for f in result.findings)

    @pytest.mark.asyncio
    async def test_outputs_sitemap_paths(self, service):
        """Check outputs sitemap_paths for downstream checks."""
        check = SitemapCheck()
        context = {}

        with patch(
            "app.checks.web.sitemap.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={("GET", "sitemap.xml"): resp(200, body=SITEMAP_XML)},
            ),
        ):
            result = await check.check_service(service, context)

        assert "sitemap_paths" in result.outputs
        assert len(result.outputs["sitemap_paths"]["all_paths"]) == 6

    @pytest.mark.asyncio
    async def test_empty_sitemap(self, service):
        """Empty sitemap body produces no findings."""
        check = SitemapCheck()
        context = {}

        with patch(
            "app.checks.web.sitemap.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={("GET", "sitemap.xml"): resp(200, body="")},
            ),
        ):
            result = await check.check_service(service, context)

        assert result.success
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_malformed_xml(self, service):
        """Malformed XML is handled gracefully."""
        check = SitemapCheck()
        context = {}

        with patch(
            "app.checks.web.sitemap.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={("GET", "sitemap.xml"): resp(200, body="<not valid xml!!!")},
            ),
        ):
            result = await check.check_service(service, context)

        assert result.success
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# RedirectChainCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestRedirectChainCheck:
    def test_init(self):
        check = RedirectChainCheck()
        assert check.name == "redirect_chain"
        assert "redirect_info" in check.produces

    @pytest.mark.asyncio
    async def test_no_https_redirect(self, service):
        """HTTP service with no HTTPS redirect is flagged."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(200, body="<html>Hello</html>"),
            ),
        ):
            result = await check.check_service(service, {})

        no_https = [f for f in result.findings if "no-https-redirect" in (f.id or "")]
        assert len(no_https) == 1
        assert no_https[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_https_redirect_present(self, service):
        """HTTP -> HTTPS redirect is correctly detected."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "http://target.com:80"): resp(
                        301, headers={"location": "https://target.com/"}
                    ),
                },
                default=resp(200),
            ),
        ):
            result = await check.check_service(service, {})

        ok = [f for f in result.findings if "https-redirect-ok" in (f.id or "")]
        assert len(ok) == 1
        assert ok[0].severity == "info"

    @pytest.mark.asyncio
    async def test_skip_https_service(self, https_service):
        """HTTPS service skips the HTTP->HTTPS check."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(200),
            ),
        ):
            result = await check.check_service(https_service, {})

        no_https = [f for f in result.findings if "no-https-redirect" in (f.id or "")]
        assert len(no_https) == 0

    @pytest.mark.asyncio
    async def test_long_chain_detected(self, service):
        """Chain with >3 hops is flagged."""
        check = RedirectChainCheck()
        call_count = 0

        async def redirect_chain(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 4:
                return resp(302, headers={"location": f"http://target.com:80/step{call_count}"})
            return resp(200, body="final")

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock()
        mock.get = AsyncMock(side_effect=redirect_chain)
        mock.post = AsyncMock(return_value=resp(200))

        with patch("app.checks.web.redirect_chain.AsyncHttpClient", return_value=mock):
            result = await check.check_service(service, {})

        long_chain = [f for f in result.findings if "long-chain" in (f.id or "")]
        assert len(long_chain) == 1

    @pytest.mark.asyncio
    async def test_open_redirect_detected(self, service):
        """Open redirect via URL parameter is flagged."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "redirect?url="): resp(
                        302, headers={"location": "https://evil.example.com"}
                    ),
                },
                default=resp(200, body="<html>OK</html>"),
            ),
        ):
            result = await check.check_service(service, {})

        open_redir = [f for f in result.findings if "open-redirect" in (f.id or "")]
        assert len(open_redir) >= 1
        assert open_redir[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_cross_domain_redirect(self, service):
        """Cross-domain redirect is reported."""
        check = RedirectChainCheck()
        call_count = 0

        async def cross_domain(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call: HTTPS redirect check
                return resp(200, body="<html>OK</html>")
            if call_count == 2:
                # Second call: chain follow - root
                return resp(302, headers={"location": "http://other-domain.com/"})
            return resp(200, body="final")

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock()
        mock.get = AsyncMock(side_effect=cross_domain)
        mock.post = AsyncMock(return_value=resp(200))

        with patch("app.checks.web.redirect_chain.AsyncHttpClient", return_value=mock):
            result = await check.check_service(service, {})

        cross = [f for f in result.findings if "cross-domain" in (f.id or "")]
        assert len(cross) == 1

    @pytest.mark.asyncio
    async def test_no_open_redirect(self, service):
        """No open redirect when redirect params are not accepted."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, {})

        open_redir = [f for f in result.findings if "open-redirect" in (f.id or "")]
        assert len(open_redir) == 0

    @pytest.mark.asyncio
    async def test_connection_error(self, service):
        """Connection errors are handled gracefully."""
        check = RedirectChainCheck()

        with patch(
            "app.checks.web.redirect_chain.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(0, error="Connection refused"),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success


# ═══════════════════════════════════════════════════════════════════════════════
# ErrorPageCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestErrorPageCheck:
    def test_init(self):
        check = ErrorPageCheck()
        assert check.name == "error_page"
        assert "error_page_info" in check.produces

    @pytest.mark.asyncio
    async def test_django_debug_detected(self, service):
        """Django DEBUG=True is detected from 404 response."""
        check = ErrorPageCheck()
        body = "<html>You're seeing this error because you have DEBUG = True in your Django settings file.</html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        django = [f for f in result.findings if "django" in (f.id or "")]
        assert len(django) == 1
        assert django[0].severity == "medium"
        assert "Debug mode" in django[0].title

    @pytest.mark.asyncio
    async def test_werkzeug_debugger_high_severity(self, service):
        """Werkzeug debugger is flagged as high severity."""
        check = ErrorPageCheck()
        body = (
            "<html><title>Werkzeug Debugger</title><p>The debugger caught an exception</p></html>"
        )

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(500, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        werkzeug = [f for f in result.findings if "werkzeug" in (f.id or "")]
        assert len(werkzeug) >= 1
        assert werkzeug[0].severity == "high"

    @pytest.mark.asyncio
    async def test_spring_boot_identified(self, service):
        """Spring Boot Whitelabel Error Page is identified."""
        check = ErrorPageCheck()
        body = "<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p></body></html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        spring = [f for f in result.findings if "spring-boot" in (f.id or "")]
        assert len(spring) == 1
        assert spring[0].severity == "low"
        assert "Framework identified" in spring[0].title

    @pytest.mark.asyncio
    async def test_express_identified(self, service):
        """Express.js Cannot GET is identified."""
        check = ErrorPageCheck()
        body = "<!DOCTYPE html><html><body><pre>Cannot GET /nonexistent-path</pre></body></html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        express = [f for f in result.findings if "express" in (f.id or "")]
        assert len(express) == 1

    @pytest.mark.asyncio
    async def test_fastapi_identified(self, service):
        """FastAPI JSON error is identified."""
        check = ErrorPageCheck()
        body = '{"detail": "Not Found"}'

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        fastapi = [f for f in result.findings if "fastapi" in (f.id or "")]
        assert len(fastapi) == 1
        assert fastapi[0].severity == "info"

    @pytest.mark.asyncio
    async def test_stack_trace_detected(self, service):
        """Python stack trace in error response is flagged."""
        check = ErrorPageCheck()
        body = """<html>
        Traceback (most recent call last)
        File "app.py", line 42
        </html>"""

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(500, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        stack = [f for f in result.findings if "stack-trace" in (f.id or "")]
        assert len(stack) == 1

    @pytest.mark.asyncio
    async def test_custom_error_pages(self, service):
        """Custom error pages with no framework signature produce info finding."""
        check = ErrorPageCheck()
        body = "<html><body><h1>Page Not Found</h1><p>Sorry, we could not find that page.</p></body></html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        custom = [f for f in result.findings if "custom-errors" in (f.id or "")]
        assert len(custom) == 1
        assert custom[0].severity == "info"

    @pytest.mark.asyncio
    async def test_outputs_error_page_info(self, service):
        """Check outputs error_page_info with frameworks and debug status."""
        check = ErrorPageCheck()
        body = "<html>Whitelabel Error Page</html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        assert "error_page_info" in result.outputs
        assert "Spring Boot" in result.outputs["error_page_info"]["frameworks"]

    @pytest.mark.asyncio
    async def test_asp_net_detected(self, service):
        """ASP.NET error page is identified."""
        check = ErrorPageCheck()
        body = "<html><body><h1>Server Error in '/' Application.</h1></body></html>"

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(500, body=body),
            ),
        ):
            result = await check.check_service(service, {})

        asp = [f for f in result.findings if "asp.net" in (f.id or "")]
        assert len(asp) == 1

    @pytest.mark.asyncio
    async def test_malformed_json_triggers_500(self, service):
        """Malformed JSON to API paths triggers error analysis."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("POST", "/api"): resp(
                        500, body='Traceback (most recent call last)\nFile "app.py", line 42'
                    ),
                },
                default=resp(404, body="not found"),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success

    @pytest.mark.asyncio
    async def test_connection_error_handled(self, service):
        """Connection errors produce no findings."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(0, error="Connection refused"),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success


# ═══════════════════════════════════════════════════════════════════════════════
# SSRFIndicatorCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestSSRFIndicatorCheck:
    def test_init(self):
        check = SSRFIndicatorCheck()
        assert check.name == "ssrf_indicator"
        assert "ssrf_candidates" in check.produces

    @pytest.mark.asyncio
    async def test_openapi_url_param_detected(self, service):
        """URL parameter in OpenAPI spec is flagged as SSRF candidate."""
        check = SSRFIndicatorCheck()
        context = {
            "openapi_spec": {
                "paths": {
                    "/api/summarize": {
                        "post": {
                            "parameters": [
                                {
                                    "name": "url",
                                    "in": "query",
                                    "schema": {"type": "string", "format": "uri"},
                                },
                            ],
                        },
                    },
                },
            },
        }

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, context)

        ssrf = [f for f in result.findings if "ssrf" in (f.id or "")]
        assert len(ssrf) >= 1
        assert any("OpenAPI" in f.title for f in ssrf)

    @pytest.mark.asyncio
    async def test_openapi_body_field_detected(self, service):
        """URL field in OpenAPI request body is flagged."""
        check = SSRFIndicatorCheck()
        context = {
            "openapi_spec": {
                "paths": {
                    "/api/analyze": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "properties": {
                                                "image_url": {"type": "string", "format": "uri"},
                                                "name": {"type": "string"},
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, context)

        ssrf = [f for f in result.findings if "ssrf" in (f.id or "")]
        assert len(ssrf) >= 1
        assert any("image_url" in f.title for f in ssrf)

    @pytest.mark.asyncio
    async def test_probe_ssrf_prone_path(self, service):
        """SSRF-prone paths returning validation errors are detected."""
        check = SSRFIndicatorCheck()

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "/api/fetch"): resp(400, body='{"error": "url parameter is required"}'),
                    ("GET", "/api/proxy"): resp(422, body='{"detail": "field required: url"}'),
                },
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, {})

        ssrf = [f for f in result.findings if "ssrf" in (f.id or "")]
        assert len(ssrf) >= 2

    @pytest.mark.asyncio
    async def test_no_ssrf_when_all_404(self, service):
        """No SSRF findings when all probed paths return 404."""
        check = SSRFIndicatorCheck()

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, {})

        ssrf = [f for f in result.findings if "ssrf" in (f.id or "")]
        assert len(ssrf) == 0

    @pytest.mark.asyncio
    async def test_discovered_paths_with_url_params(self, service):
        """URL params in discovered paths are flagged."""
        check = SSRFIndicatorCheck()
        context = {
            "discovered_paths": {
                "all_paths": [
                    "/page?id=1",
                    "/proxy?url=http://internal",
                    "/view?name=test",
                ],
            },
        }

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, context)

        ssrf = [f for f in result.findings if "ssrf" in (f.id or "")]
        # Should find /proxy?url= but not /page?id= or /view?name=
        url_param_findings = [f for f in ssrf if "url" in f.title.lower()]
        assert len(url_param_findings) >= 1

    @pytest.mark.asyncio
    async def test_outputs_ssrf_candidates(self, service):
        """Check outputs ssrf_candidates list."""
        check = SSRFIndicatorCheck()
        context = {
            "openapi_spec": {
                "paths": {
                    "/api/fetch": {
                        "get": {
                            "parameters": [
                                {"name": "url", "in": "query", "schema": {"type": "string"}},
                            ],
                        },
                    },
                },
            },
        }

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, context)

        assert "ssrf_candidates" in result.outputs
        assert isinstance(result.outputs["ssrf_candidates"], list)

    @pytest.mark.asyncio
    async def test_proxy_param_medium_severity(self, service):
        """Proxy/fetch parameters get medium severity via OpenAPI."""
        check = SSRFIndicatorCheck()
        context = {
            "openapi_spec": {
                "paths": {
                    "/api/proxy": {
                        "get": {
                            "parameters": [
                                {"name": "proxy", "in": "query", "schema": {"type": "string"}},
                            ],
                        },
                    },
                },
            },
        }

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, context)

        proxy_findings = [f for f in result.findings if "proxy" in (f.id or "")]
        assert len(proxy_findings) >= 1
        assert proxy_findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_deduplication(self, service):
        """Same path from multiple sources is deduplicated."""
        check = SSRFIndicatorCheck()
        context = {
            "openapi_spec": {
                "paths": {
                    "/api/fetch": {
                        "get": {
                            "parameters": [
                                {"name": "url", "in": "query", "schema": {"type": "string"}},
                            ],
                        },
                    },
                },
            },
            "discovered_paths": {
                "all_paths": ["/api/fetch?url=http://test"],
            },
        }

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, context)

        # /api/fetch should appear only once despite being in both sources
        fetch_findings = [f for f in result.findings if "api-fetch" in (f.id or "")]
        assert len(fetch_findings) == 1

    @pytest.mark.asyncio
    async def test_connection_error_handled(self, service):
        """Connection errors don't crash the check."""
        check = SSRFIndicatorCheck()

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(0, error="Connection refused"),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success

    @pytest.mark.asyncio
    async def test_form_with_url_input(self, service):
        """HTML form with type='url' input is detected."""
        check = SSRFIndicatorCheck()

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "/api/preview"): resp(
                        200, body='<form><input type="url" name="url" /></form>'
                    ),
                },
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, {})

        ssrf = [f for f in result.findings if "preview" in (f.id or "")]
        assert len(ssrf) >= 1
