"""Tests for cag_cache_quota.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_cache_quota import CacheQuotaCheck
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
        ],
        "cache_infrastructure": ["gptcache"],
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
    """Report the response as coming from the URL it was requested from.

    A probe records `HttpResponse.url` as the exchange's `request_url`, and a
    grader attributes each exchange back to its endpoint from there. A mock
    that stamps one fixed url onto every response makes every exchange look
    like the same request (§0.13).
    """
    return replace(response, url=url) if url else response


def _stamped(fn):
    """Wrap a client method so whatever it returns is stamped with its URL.

    Finds the URL as the `url=` keyword or the first positional string that
    looks like one, which covers both `post(url, ...)` and
    `_request("DELETE", url)`.
    """

    async def _call(*args, **kwargs):
        url = kwargs.get("url")
        if url is None:
            url = next((a for a in args if isinstance(a, str) and "://" in a), None)
        response = await fn(*args, **kwargs)
        return _stamp(response, url) if isinstance(response, HttpResponse) else response

    return AsyncMock(side_effect=_call)


def make_mock_client(**overrides):
    """Create a standard mock HTTP client.

    Every method stamps the requested URL onto its response, and `__aexit__`
    returns False: a bare `AsyncMock()` returns a truthy MagicMock, which
    suppresses every exception raised inside the `async with` (§0.14).
    """
    client = AsyncMock()
    client.get = _stamped(AsyncMock(return_value=make_response(status_code=404)))
    client.post = _stamped(
        AsyncMock(return_value=make_response(status_code=200, body='{"answer": "ok"}'))
    )
    client.head = _stamped(AsyncMock(return_value=make_response(status_code=404)))
    client._request = _stamped(AsyncMock(return_value=make_response(status_code=404)))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    for k, v in overrides.items():
        setattr(client, k, _stamped(v) if callable(v) else v)
    return client


async def probe_and_grade(check, service, context):
    """Run the probe, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.check_service(service, context)
    return await grade_result(check, result, context)


class TestCacheQuotaCheck:
    @pytest.fixture
    def check(self):
        return CacheQuotaCheck()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await probe_and_grade(check, sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_detects_eviction(self, check, sample_service, cag_endpoint_context):
        """When early entries are evicted, reports cache exhaustion."""
        quota_info = {
            "url": "http://cag.example.com:8080/cache",
            "total_entries_sent": 50,
            "early_entries_evicted": 3,
            "early_entries_checked": 5,
            "last_entries_cached": 3,
            "baseline_ms": 200.0,
            "cached_ms": 30.0,
            "eviction_detected": True,
            "unbounded": False,
            "estimated_capacity": 47,
        }
        with patch.object(check, "_test_quota", return_value=quota_info):
            client = make_mock_client()
            with patch("app.checks.cag.cag_cache_quota.check.AsyncHttpClient", return_value=client):
                result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert "Cache exhaustion possible" in obs.title
        assert "3 early entries evicted" in obs.title
        assert obs.severity == "medium"
        assert result.outputs["cache_size"] == [quota_info]

    @pytest.mark.asyncio
    async def test_detects_unbounded_cache(self, check, sample_service, cag_endpoint_context):
        """When no eviction occurs, reports unbounded cache risk."""
        quota_info = {
            "url": "http://cag.example.com:8080/cache",
            "total_entries_sent": 50,
            "early_entries_evicted": 0,
            "early_entries_checked": 5,
            "last_entries_cached": 3,
            "baseline_ms": 200.0,
            "cached_ms": 30.0,
            "eviction_detected": False,
            "unbounded": True,
            "estimated_capacity": 50,
        }
        with patch.object(check, "_test_quota", return_value=quota_info):
            client = make_mock_client()
            with patch("app.checks.cag.cag_cache_quota.check.AsyncHttpClient", return_value=client):
                result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert "Unbounded cache" in obs.title
        assert "memory exhaustion risk" in obs.title
        assert obs.severity == "medium"

    @pytest.mark.asyncio
    async def test_no_caching_detected_produces_no_observations(
        self, check, sample_service, cag_endpoint_context
    ):
        """When _test_quota returns None (no caching), no observations."""
        with patch.object(check, "_test_quota", return_value=None):
            client = make_mock_client()
            with patch("app.checks.cag.cag_cache_quota.check.AsyncHttpClient", return_value=client):
                result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0
        assert "cache_size" not in result.outputs
