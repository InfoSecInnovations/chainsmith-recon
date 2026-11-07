"""Tests for cag_cache_key_reverse.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions. Timing is now driven by
each mock response's `elapsed_ms` (recorded on the exchange and read back by
`grade()`), not by patching `time.time` (§0.12).
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_cache_key_reverse import CacheKeyReverseCheck
from app.checks.cag.cag_cache_key_reverse.check import BASELINE_PREFIX
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
    elapsed_ms: float = 50.0,
    url: str = "http://cag.example.com:8080/test",
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=elapsed_ms,
        error=error,
    )


def _stamp(response: HttpResponse, url: str | None) -> HttpResponse:
    return replace(response, url=url) if url else response


def make_mock_client(**overrides):
    """Create a standard mock HTTP client (`__aexit__` returns False, §0.14)."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=make_response(status_code=404))
    client.post = AsyncMock(return_value=make_response(status_code=200, body='{"answer": "ok"}'))
    client.head = AsyncMock(return_value=make_response(status_code=404))
    client._request = AsyncMock(return_value=make_response(status_code=404))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    for k, v in overrides.items():
        setattr(client, k, v)
    return client


async def probe_and_grade(check, service, context):
    """Run the probe, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.check_service(service, context)
    return await grade_result(check, result, context)


class TestCacheKeyReverseCheck:
    @pytest.fixture
    def check(self):
        return CacheKeyReverseCheck()

    @pytest.mark.asyncio
    async def test_detects_case_insensitive_key(self, check, sample_service, cag_endpoint_context):
        """When variant queries answer fast (cache hit), the component is NOT in the key.

        Baseline: first (uncached) read 500ms, second (cached) read 100ms — under
        70% of 500, so caching is detected and the hit threshold is 350ms. Every
        variant query (and the system_b variant) answers at 100ms, so each reads
        as a cache hit: the component / system prompt is excluded from the key.
        """
        baseline_calls = 0

        async def mock_post(url, **kwargs):
            nonlocal baseline_calls
            body = kwargs.get("json", {})
            query = body.get("input", "")
            if BASELINE_PREFIX in query:
                baseline_calls += 1
                elapsed = 500.0 if baseline_calls == 1 else 100.0
            else:
                # Populate (base) and variant requests: fast. Only variants are
                # graded, and a fast variant (100ms < 350ms) is a cache hit.
                elapsed = 100.0
            return _stamp(
                make_response(status_code=200, body='{"answer": "Paris."}', elapsed_ms=elapsed),
                url,
            )

        client = make_mock_client(post=AsyncMock(side_effect=mock_post))
        with (
            patch(
                "app.checks.cag.cag_cache_key_reverse.check.AsyncHttpClient", return_value=client
            ),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        # Should detect system prompt exclusion (high) and case/whitespace insensitivity (medium)
        high_obs = [o for o in result.observations if o.severity == "high"]
        assert len(high_obs) >= 1
        assert "system prompt" in high_obs[0].title.lower()

        medium_obs = [o for o in result.observations if o.severity == "medium"]
        assert len(medium_obs) >= 1

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await probe_and_grade(check, sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_no_caching_detected_produces_no_observations(
        self, check, sample_service, cag_endpoint_context
    ):
        """When the endpoint doesn't cache, baseline detection fails: no observations.

        Both baseline reads take ~500ms (cached is not < 70% of uncached), so
        caching is never detected and no key tests are graded.
        """

        async def mock_post(url, **kwargs):
            return _stamp(
                make_response(
                    status_code=200,
                    body='{"answer": "dynamic response"}',
                    elapsed_ms=500.0,
                ),
                url,
            )

        client = make_mock_client(post=AsyncMock(side_effect=mock_post))
        with (
            patch(
                "app.checks.cag.cag_cache_key_reverse.check.AsyncHttpClient", return_value=client
            ),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0
