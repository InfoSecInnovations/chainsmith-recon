"""Tests for cag_multi_layer_cache.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions. `_detect_layers` no
longer exists — the two detection tests now drive the real analysis with mock
responses whose `elapsed_ms` and cache headers vary by strategy (recovered from
each recorded request), which is what the probe records and `grade()` reads
back (§0.12).
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_multi_layer_cache import MultiLayerCacheCheck
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


def _strategy(headers: dict, body: dict) -> str:
    """Same recovery the grader does: strategy from request headers/body."""
    if "_cb" in body:
        return "cache_buster"
    low = {k.lower(): v.lower() for k, v in headers.items()}
    if low.get("cache-control") == "no-cache":
        return "no_cache"
    if low.get("pragma") == "no-cache":
        return "pragma"
    return "normal"


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


def _timed_client(latency_by_strategy: dict):
    """A client whose POST latency depends on the request's bypass strategy."""

    async def mock_post(url, **kwargs):
        body = kwargs.get("json", {})
        headers = kwargs.get("headers", {})
        strategy = _strategy(headers, body)
        return _stamp(
            make_response(
                status_code=200,
                body='{"answer": "response"}',
                elapsed_ms=latency_by_strategy[strategy],
            ),
            url,
        )

    return make_mock_client(post=AsyncMock(side_effect=mock_post))


async def probe_and_grade(check, service, context):
    """Run the probe, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.check_service(service, context)
    return await grade_result(check, result, context)


class TestMultiLayerCacheCheck:
    @pytest.fixture
    def check(self):
        return MultiLayerCacheCheck()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await probe_and_grade(check, sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_detects_multiple_layers(self, check, sample_service, cag_endpoint_context):
        """Two layers: HTTP cache (bypassed by no-cache/pragma) + application cache.

        normal 20ms, no_cache/pragma 50ms (>1.5x normal -> HTTP cache bypassed),
        cache_buster 200ms (no_cache < buster*0.7 -> a second layer).
        """
        client = _timed_client(
            {"normal": 20.0, "no_cache": 50.0, "pragma": 45.0, "cache_buster": 200.0}
        )
        with patch(
            "app.checks.cag.cag_multi_layer_cache.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert (
            obs.title == "Multiple cache layers detected: 2 layers with different bypass behavior"
        )
        assert obs.severity == "medium"
        assert result.outputs["cache_layers"][0]["layers_detected"] == 2

    @pytest.mark.asyncio
    async def test_detects_single_semantic_layer(self, check, sample_service, cag_endpoint_context):
        """Single semantic cache layer: all strategies fast and uniform -> info severity."""
        client = _timed_client(
            {"normal": 20.0, "no_cache": 22.0, "pragma": 21.0, "cache_buster": 23.0}
        )
        with patch(
            "app.checks.cag.cag_multi_layer_cache.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Single cache layer detected (semantic_or_application_cache)"
        assert obs.severity == "info"

    @pytest.mark.asyncio
    async def test_no_layers_detected_produces_no_observations(
        self, check, sample_service, cag_endpoint_context
    ):
        """When no timing pattern indicates a layer, no observation is emitted.

        All strategies slow (>500ms) and uniform: no HTTP-cache bypass, and the
        single-layer branch requires normal < 500ms, so `_analyze_layers` finds
        nothing and `grade()` returns no verdict.
        """
        client = _timed_client(
            {"normal": 600.0, "no_cache": 610.0, "pragma": 605.0, "cache_buster": 620.0}
        )
        with patch(
            "app.checks.cag.cag_multi_layer_cache.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0
        assert "cache_layers" not in result.outputs

    @pytest.mark.asyncio
    async def test_strategy_recovered_from_request(self):
        """The grader tells the four strategies apart by the recorded request."""
        assert _strategy({}, {"input": "q"}) == "normal"
        assert _strategy({"Cache-Control": "no-cache"}, {}) == "no_cache"
        assert _strategy({"Pragma": "no-cache"}, {}) == "pragma"
        assert _strategy({}, {"_cb": "123"}) == "cache_buster"
        # sanity: json round-trips the buster marker the grader parses
        assert "_cb" in json.loads(json.dumps({"_cb": "123"}))
