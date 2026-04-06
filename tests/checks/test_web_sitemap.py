"""Tests for SitemapCheck — sitemap discovery and parsing."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.sitemap import SitemapCheck
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
