"""Tests for cag_ttl_mapping.

This check is split into probe + grade; tests route through
`probe_and_grade()`. The three timing tests used to `patch.object` the internal
`_map_ttl` to hand it a pre-built `ttl_info` dict — but in the split there is no
such return value to intercept: the probe records exchanges and `grade()`
re-derives the reading off their recorded `elapsed_ms`. So those tests now drive
the real timing sequence through a call-counting HTTP mock that returns faithful
`elapsed_ms` per request, which is what the directive asks for (make the mock
produce faithful timing rather than weaken the assertion). Titles and severities
are asserted verbatim; the old exact-`ttl_info`-dict equality is replaced by
assertions on the meaningful derived fields.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_ttl_mapping import TTLMappingCheck
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
) -> HttpResponse:
    """Create a mock HTTP response with a controllable elapsed time."""
    return HttpResponse(
        url="http://cag.example.com:8080/cache",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=elapsed_ms,
        error=error,
    )


def timed_client(timings):
    """A mock client whose Nth POST returns the Nth `(elapsed_ms, headers)` pair.

    Requests past the list reuse the last pair, which models a cache that keeps
    hitting. `__aexit__` returns False so a probe exception is not suppressed
    (§0.14).
    """
    client = AsyncMock()
    state = {"i": 0}

    async def _post(url=None, **kwargs):
        i = min(state["i"], len(timings) - 1)
        elapsed, headers = timings[i]
        state["i"] += 1
        return make_response(
            status_code=200, body='{"answer": "ok"}', headers=headers, elapsed_ms=elapsed
        )

    client.post = AsyncMock(side_effect=_post)
    client.get = AsyncMock(return_value=make_response(status_code=404))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


async def probe_and_grade(check, service, context):
    """Run the probe, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.check_service(service, context)
    return await grade_result(check, result, context)


class TestTTLMappingCheck:
    @pytest.fixture
    def check(self):
        return TTLMappingCheck()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await probe_and_grade(check, sample_service, {})
        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_detects_unbounded_ttl(self, check, sample_service, cag_endpoint_context):
        """Every re-query stays fast (a cache hit), so no expiry is found."""
        # initial slow, then every subsequent request is a hit -> unbounded.
        timings = [(200.0, {})] + [(30.0, {})] * 5
        client = timed_client(timings)
        with (
            patch("app.checks.cag.cag_ttl_mapping.check.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Unbounded cache TTL (no expiry detected within test window)"
        assert obs.severity == "medium"
        reading = result.outputs["cache_ttl"][0]
        assert reading["caching_detected"]
        assert reading["ttl_unbounded"]
        assert reading["initial_request_ms"] == 200.0
        assert reading["cached_request_ms"] == 30.0

    @pytest.mark.asyncio
    async def test_detects_ttl_mismatch(self, check, sample_service, cag_endpoint_context):
        """Header says max-age=60 but the entry expires at the 15s probe."""
        # initial (with header), confirm hit, 5s hit, 15s miss.
        timings = [
            (200.0, {"cache-control": "max-age=60"}),
            (30.0, {"cache-control": "max-age=60"}),
            (30.0, {"cache-control": "max-age=60"}),  # 5s: hit
            (200.0, {"cache-control": "max-age=60"}),  # 15s: miss
        ]
        client = timed_client(timings)
        with (
            patch("app.checks.cag.cag_ttl_mapping.check.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert "mismatch" in obs.title.lower()
        assert obs.severity == "low"
        reading = result.outputs["cache_ttl"][0]
        assert reading["header_ttl_seconds"] == 60
        assert reading["observed_ttl_seconds"] == 15
        assert reading["ttl_mismatch"]

    @pytest.mark.asyncio
    async def test_no_caching_detected_produces_no_observations(
        self, check, sample_service, cag_endpoint_context
    ):
        """Second request is no faster than the first -> no caching, no obs."""
        timings = [(200.0, {}), (200.0, {})]
        client = timed_client(timings)
        with (
            patch("app.checks.cag.cag_ttl_mapping.check.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0
        assert "cache_ttl" not in result.outputs
