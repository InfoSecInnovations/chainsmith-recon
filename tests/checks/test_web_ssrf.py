"""Tests for SSRFIndicatorCheck — SSRF indicator detection."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
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
