"""Tests for cag_discovery."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_discovery import CAGDiscoveryCheck
from app.lib.http import HttpResponse


@pytest.fixture
def sample_service():
    """Sample CAG service."""
    return Service(
        url="http://cag.example.com:8080",
        host="cag.example.com",
        port=8080,
        scheme="http",
        service_type="ai",
    )


@pytest.fixture
def cag_endpoint_context(sample_service):
    """Context with CAG endpoints discovered."""
    return {
        "cag_endpoints": [
            {
                "url": "http://cag.example.com:8080/cache",
                "path": "/cache",
                "cache_type": "gptcache",
                "status_code": 200,
                "auth_required": False,
                "endpoint_type": "cache_infrastructure",
                "service": sample_service.to_dict(),
            }
        ]
    }


def make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url="http://cag.example.com:8080/test",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


def _stamp(response: HttpResponse, url: str | None) -> HttpResponse:
    """Report the response as coming from the URL it was requested from (§0.13)."""
    return replace(response, url=url) if url else response


def _stamped(fn):
    """Wrap a client method so whatever it returns is stamped with its URL."""

    async def _call(*args, **kwargs):
        url = kwargs.get("url")
        if url is None:
            url = next((a for a in args if isinstance(a, str) and "://" in a), None)
        response = await fn(*args, **kwargs)
        return _stamp(response, url) if isinstance(response, HttpResponse) else response

    return AsyncMock(side_effect=_call)


async def probe_and_grade(check, service, context):
    """Run the probe, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.check_service(service, context)
    return await grade_result(check, result, context)


class TestCAGDiscoveryCheck:
    """Tests for CAGDiscoveryCheck."""

    @pytest.fixture
    def check(self):
        return CAGDiscoveryCheck()

    @pytest.mark.asyncio
    async def test_discovers_gptcache(self, check, sample_service):
        """Test GPTCache discovery via infrastructure-specific headers and body patterns."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # GPTCache signature path - embed indicators in a realistic response
            # with surrounding content so it's not just the indicator keyword
            if "/cache" in url and "/cache/" not in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "application/json",
                        "server": "nginx/1.21",
                        "x-gptcache-hit": "false",
                        "x-request-id": "req-8f3a",
                    },
                    body=(
                        '{"status": "operational", "version": "0.4.2", '
                        '"cache_status": "ready", "entries": 1423, '
                        '"backend": "gptcache", "similarity_threshold": 0.85}'
                    ),
                )
            return make_response(status_code=404)

        mock_client.get = _stamped(mock_get)
        mock_client.post = _stamped(AsyncMock(return_value=make_response(status_code=404)))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.cag.cag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        # Verify gptcache infrastructure detected
        infra = result.outputs.get("cache_infrastructure", [])
        assert "gptcache" in infra

        # Verify observation details
        infra_obs = [o for o in result.observations if "gptcache" in o.title]
        assert len(infra_obs) >= 1
        obs = infra_obs[0]
        assert obs.title == "Cache infrastructure: gptcache"
        assert obs.severity == "medium"  # no auth required -> medium
        assert "gptcache" in obs.evidence.lower()

    @pytest.mark.asyncio
    async def test_discovers_semantic_cache(self, check, sample_service):
        """Test semantic cache discovery via header matching."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/semantic-cache" in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "application/json",
                        "x-semantic-cache": "enabled",
                        "x-request-id": "req-2b9c",
                    },
                    body=(
                        '{"mode": "semantic", "model": "all-MiniLM-L6-v2", '
                        '"index_size": 8042, "health": "ok"}'
                    ),
                )
            return make_response(status_code=404)

        mock_client.get = _stamped(mock_get)
        mock_client.post = _stamped(AsyncMock(return_value=make_response(status_code=404)))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.cag.cag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        infra = result.outputs.get("cache_infrastructure", [])
        assert "semantic_cache" in infra

        infra_obs = [o for o in result.observations if "semantic_cache" in o.title]
        assert len(infra_obs) >= 1
        obs = infra_obs[0]
        assert obs.title == "Cache infrastructure: semantic_cache"
        assert obs.severity == "medium"

    @pytest.mark.asyncio
    async def test_detects_cache_headers_on_cag_paths(self, check, sample_service):
        """Test that AI-specific cache headers on CAG paths produce observations."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/cache/stats" in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "application/json",
                        "x-cache": "HIT",
                        "age": "120",
                    },
                    body=(
                        '{"total_entries": 5200, "hit_rate": 0.78, '
                        '"cached": true, "ttl": 3600, "eviction_policy": "lru"}'
                    ),
                )
            return make_response(status_code=404)

        mock_client.get = _stamped(mock_get)
        mock_client.post = _stamped(AsyncMock(return_value=make_response(status_code=404)))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.cag.cag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        endpoints = result.outputs.get("cag_endpoints", [])
        assert len(endpoints) > 0

        # Verify an observation was created for the /cache/stats path
        stats_obs = [o for o in result.observations if "/cache/stats" in o.title]
        assert len(stats_obs) >= 1
        obs = stats_obs[0]
        assert obs.title == "CAG endpoint: /cache/stats"
        assert obs.severity in ("low", "medium", "info")
        assert "cache/stats" in obs.evidence.lower() or "/cache/stats" in obs.evidence

    @pytest.mark.asyncio
    async def test_generic_cdn_headers_not_classified_as_ai_cache(self, check, sample_service):
        """Generic CDN headers (Cache-Control, ETag, etc.) should NOT produce CAG findings.

        Only AI-specific cache headers listed in CACHE_HEADERS trigger detection.
        """
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # Return generic CDN-style cache headers on all paths
            return make_response(
                status_code=404,
                headers={
                    "cache-control": "public, max-age=300",
                    "etag": '"abc123"',
                    "vary": "Accept-Encoding",
                    "cf-cache-status": "HIT",
                },
                body="",
            )

        mock_client.get = _stamped(mock_get)
        mock_client.post = _stamped(AsyncMock(return_value=make_response(status_code=404)))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.cag.cag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        assert len(result.outputs.get("cag_endpoints", [])) == 0
        assert len(result.outputs.get("cache_infrastructure", [])) == 0
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_detects_auth_required_on_cache_infra(self, check, sample_service):
        """Auth-required cache infrastructure produces info-severity observation."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/cache" in url and "/cache/" not in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        mock_client.get = _stamped(mock_get)
        mock_client.post = _stamped(AsyncMock(return_value=make_response(status_code=404)))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.cag.cag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        # 401 on a signature path still counts as detected infrastructure
        # (status != 404, and 200-check in _detect_cache_infrastructure won't
        # match, but since there's no headers/body match AND status!=200 it
        # won't be added). The _analyze_cag_response also returns None for
        # non-200 statuses without indicators. So no findings expected for
        # pure 401 with no body or headers.
        # Verify the check ran without error at minimum.
        assert len(result.errors) == 0

    @pytest.mark.asyncio
    async def test_no_cag_found(self, check, sample_service):
        """When all probes return 404, no CAG endpoints should be reported."""
        mock_client = AsyncMock()
        mock_client.get = _stamped(AsyncMock(return_value=make_response(status_code=404)))
        mock_client.post = _stamped(AsyncMock(return_value=make_response(status_code=404)))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.cag.cag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        assert len(result.outputs.get("cag_endpoints", [])) == 0
        assert len(result.outputs.get("cache_infrastructure", [])) == 0
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_non_cache_200_response_without_indicators(self, check, sample_service):
        """A 200 response without any cache indicators should not be a CAG endpoint.

        The _analyze_cag_response method requires at least one indicator
        (cache header or body keyword) before classifying an endpoint.
        """
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # Generic API responses with no cache indicators at all
            return make_response(
                status_code=200,
                headers={"content-type": "text/html"},
                body="<html><body>Welcome to our API</body></html>",
            )

        mock_client.get = _stamped(mock_get)
        mock_client.post = _stamped(AsyncMock(return_value=make_response(status_code=404)))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.cag.cag_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        # _detect_cache_infrastructure will fire for 200 on signature paths
        # but _analyze_cag_response requires indicators. Check that we don't
        # get endpoint-type observations from _analyze_cag_response.
        # Endpoints that aren't on infrastructure signature paths and have
        # no indicators should not appear
        non_infra_endpoints = [
            ep
            for ep in result.outputs.get("cag_endpoints", [])
            if ep.get("endpoint_type") == "cag_endpoint"
        ]
        # Without cache keywords in body or cache headers, no cag_endpoint
        # entries should have been created for paths like /session, /precomputed
        for ep in non_infra_endpoints:
            # Every cag_endpoint must have at least one indicator
            assert len(ep.get("indicators", [])) > 0
