"""Tests for cag_semantic_threshold.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_semantic_threshold import SemanticThresholdCheck
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
    """Create a mock HTTP response.

    `elapsed_ms` is faithful: the check reads request latency back off the
    recorded exchange (§0.15), so a timing-driven test drives the cold/hot/miss
    distinction through this value rather than by patching `time.time`.
    """
    return HttpResponse(
        url="http://cag.example.com:8080/test",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=elapsed_ms,
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


class TestSemanticThresholdCheck:
    @pytest.fixture
    def check(self):
        return SemanticThresholdCheck()

    @pytest.mark.asyncio
    async def test_detects_loose_semantic_threshold(
        self, check, sample_service, cag_endpoint_context
    ):
        """When many rephrased/related queries produce cache hits, a loose threshold is flagged."""
        baseline_body = (
            '{"response": "The capital of France is Paris, a city known for the Eiffel Tower."}'
        )

        # Faithful latency: cold=500ms, hot=50ms (caching confirmed), all five
        # variations=50ms (all cache hits) -> hits>=4 -> is_semantic, high.
        elapsed = iter([500.0, 50.0, 50.0, 50.0, 50.0, 50.0, 50.0])

        async def mock_post(url, **kwargs):
            return make_response(
                status_code=200, body=baseline_body, elapsed_ms=next(elapsed, 50.0)
            )

        client = make_mock_client(post=mock_post)
        with (
            patch(
                "app.checks.cag.cag_semantic_threshold.check.AsyncHttpClient", return_value=client
            ),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) >= 1
        # 5 hits with rephrased/related/tangential -> is_semantic=True, hits>=4 -> high
        obs = result.observations[0]
        assert obs.severity in ("high", "medium")
        assert "semantic" in obs.title.lower() or "threshold" in obs.title.lower()

    @pytest.mark.asyncio
    async def test_exact_match_only_reports_info(self, check, sample_service, cag_endpoint_context):
        """When no variations hit the cache, it's not a semantic cache -> info."""
        call_count = 0
        # cold=500ms, hot=50ms (caching confirmed), all five variations=600ms
        # (all miss) -> hits=0 -> not a semantic cache -> info.
        elapsed = iter([500.0, 50.0, 600.0, 600.0, 600.0, 600.0, 600.0])

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            return make_response(
                status_code=200,
                body=f'{{"response": "answer-{call_count}", "id": {call_count}}}',
                elapsed_ms=next(elapsed, 600.0),
            )

        client = make_mock_client(post=mock_post)
        with (
            patch(
                "app.checks.cag.cag_semantic_threshold.check.AsyncHttpClient", return_value=client
            ),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) >= 1
        obs = result.observations[0]
        assert obs.severity == "info"
        assert "not a semantic cache" in obs.title.lower() or "exact match" in obs.title.lower()

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await probe_and_grade(check, sample_service, {})
        assert result.success
        assert len(result.observations) == 0
