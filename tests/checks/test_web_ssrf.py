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

        ssrf = [f for f in result.observations if "ssrf" in (f.id or "")]
        assert len(ssrf) == 1
        assert "OpenAPI" in ssrf[0].title
        assert "url" in ssrf[0].title.lower()
        assert ssrf[0].severity == "medium"
        assert "OpenAPI spec" in ssrf[0].evidence

        candidates = result.outputs["ssrf_candidates"]
        assert len(candidates) == 1
        assert candidates[0]["path"] == "/api/summarize"
        assert candidates[0]["source"] == "openapi"

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

        ssrf = [f for f in result.observations if "ssrf" in (f.id or "")]
        assert len(ssrf) == 1
        assert "image_url" in ssrf[0].title
        assert ssrf[0].severity == "medium"
        assert "body field 'image_url'" in ssrf[0].evidence

    @pytest.mark.asyncio
    async def test_openapi_no_url_params_clean(self, service):
        """OpenAPI spec with no URL params produces no SSRF observations."""
        check = SSRFIndicatorCheck()
        context = {
            "openapi_spec": {
                "paths": {
                    "/api/users": {
                        "get": {
                            "parameters": [
                                {"name": "page", "in": "query", "schema": {"type": "integer"}},
                                {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                            ],
                        },
                    },
                },
            },
        }

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(404)),
        ):
            result = await check.check_service(service, context)

        ssrf = [f for f in result.observations if "ssrf" in (f.id or "")]
        assert len(ssrf) == 0
        assert result.outputs["ssrf_candidates"] == []

    @pytest.mark.asyncio
    async def test_probe_ssrf_prone_path_validation_error(self, service):
        """SSRF-prone paths returning validation errors mentioning URL params are detected."""
        check = SSRFIndicatorCheck()

        # Realistic: a 400 response that mentions the missing 'url' field,
        # and a 422 that mentions the required 'url' field
        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "/api/fetch"): resp(
                        400,
                        body='{"error": "Missing required parameter", "detail": "url is required"}',
                    ),
                    ("GET", "/api/proxy"): resp(
                        422,
                        body='{"detail": [{"loc": ["query", "url"], "msg": "field required"}]}',
                    ),
                },
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, {})

        ssrf = [f for f in result.observations if "ssrf" in (f.id or "")]
        assert len(ssrf) == 2

        fetch_obs = [f for f in ssrf if "api-fetch" in (f.id or "")]
        assert len(fetch_obs) == 1
        assert "url" in fetch_obs[0].description.lower()

        proxy_obs = [f for f in ssrf if "api-proxy" in (f.id or "")]
        assert len(proxy_obs) == 1

    @pytest.mark.asyncio
    async def test_probe_200_with_url_form_input(self, service):
        """SSRF-prone path returning HTML form with type='url' input is detected."""
        check = SSRFIndicatorCheck()

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "/api/preview"): resp(
                        200,
                        body='<form action="/api/preview" method="post"><input type="url" name="target_url" /><button>Preview</button></form>',
                    ),
                },
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, {})

        ssrf = [f for f in result.observations if "preview" in (f.id or "")]
        assert len(ssrf) == 1
        assert "url" in ssrf[0].description.lower()
        assert ssrf[0].severity in ("low", "medium")

    @pytest.mark.asyncio
    async def test_probe_200_without_url_hints_not_flagged(self, service):
        """SSRF-prone path returning 200 without URL hints is not flagged."""
        check = SSRFIndicatorCheck()

        # Returns 200 but body does not suggest URL parameter
        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("GET", "/api/fetch"): resp(
                        200,
                        body="<html><body><h1>Welcome to our API</h1></body></html>",
                    ),
                },
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, {})

        fetch_obs = [f for f in result.observations if "api-fetch" in (f.id or "")]
        assert len(fetch_obs) == 0

    @pytest.mark.asyncio
    async def test_no_ssrf_when_all_404(self, service):
        """No SSRF observations when all probed paths return 404."""
        check = SSRFIndicatorCheck()

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404),
            ),
        ):
            result = await check.check_service(service, {})

        ssrf = [f for f in result.observations if "ssrf" in (f.id or "")]
        assert len(ssrf) == 0
        assert result.outputs["ssrf_candidates"] == []

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

        ssrf = [f for f in result.observations if "ssrf" in (f.id or "")]
        # Should find /proxy?url= but not /page?id= or /view?name=
        assert len(ssrf) == 1
        assert "url" in ssrf[0].title.lower()
        assert ssrf[0].severity == "low"
        assert "discovered" in result.outputs["ssrf_candidates"][0]["source"]

    @pytest.mark.asyncio
    async def test_discovered_paths_without_url_params_clean(self, service):
        """Discovered paths without URL-accepting params produce no SSRF observations."""
        check = SSRFIndicatorCheck()
        context = {
            "discovered_paths": {
                "all_paths": [
                    "/page?id=1",
                    "/search?q=test",
                    "/view?name=hello",
                ],
            },
        }

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(404)),
        ):
            result = await check.check_service(service, context)

        ssrf = [f for f in result.observations if "ssrf" in (f.id or "")]
        assert len(ssrf) == 0

    @pytest.mark.asyncio
    async def test_outputs_ssrf_candidates_structure(self, service):
        """Check outputs ssrf_candidates list with expected fields."""
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
        candidates = result.outputs["ssrf_candidates"]
        assert isinstance(candidates, list)
        assert len(candidates) == 1
        assert candidates[0]["path"] == "/api/fetch"
        assert candidates[0]["param"] == "url"
        assert candidates[0]["source"] == "openapi"

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

        proxy_observations = [f for f in result.observations if "proxy" in (f.id or "")]
        assert len(proxy_observations) == 1
        assert proxy_observations[0].severity == "medium"
        assert "'proxy'" in proxy_observations[0].title

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
        fetch_observations = [f for f in result.observations if "api-fetch" in (f.id or "")]
        assert len(fetch_observations) == 1
        assert len(result.outputs["ssrf_candidates"]) == 1

    @pytest.mark.asyncio
    async def test_connection_error_handled(self, service):
        """Connection errors don't crash the check, error is recorded."""
        check = SSRFIndicatorCheck()

        with patch(
            "app.checks.web.ssrf_indicator.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(0, error="Connection refused"),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success
        # No SSRF observations from errored responses
        ssrf = [f for f in result.observations if "ssrf" in (f.id or "")]
        assert len(ssrf) == 0

    @pytest.mark.asyncio
    async def test_exception_in_http_client(self, service):
        """Unhandled exception in HTTP client is caught and recorded."""
        check = SSRFIndicatorCheck()

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        mock.get = AsyncMock(side_effect=OSError("Network unreachable"))

        with patch("app.checks.web.ssrf_indicator.AsyncHttpClient", return_value=mock):
            result = await check.check_service(service, {})

        assert len(result.errors) >= 1
        assert "SSRF probe error" in result.errors[0]
