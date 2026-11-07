"""Tests for cag_cache_poisoning.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_cache_poisoning import CachePoisoningCheck
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


class TestCachePoisoningCheck:
    @pytest.fixture
    def check(self):
        return CachePoisoningCheck()

    @pytest.mark.asyncio
    async def test_detects_exact_poisoning(self, check, sample_service, cag_endpoint_context):
        """Marker found in cross-session response = critical poisoning confirmed.

        The check injects a query containing CACHE_POISON_MARKER_<uuid> and then
        reads it back from a different session. If the marker appears in the second
        response, poisoning is confirmed.
        """
        stored_response = {}

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            input_text = body.get("input", "")

            # When the poison query comes in, store the response and echo it back
            # in a realistic LLM response wrapper that embeds the marker naturally
            if "CACHE_POISON_MARKER_" in input_text:
                # Extract marker from the query text
                # Query format: "What is the capital of France? [CACHE_POISON_MARKER_xxxx]"
                marker_start = input_text.find("CACHE_POISON_MARKER_")
                bracket_end = input_text.find("]", marker_start)
                marker = (
                    input_text[marker_start:bracket_end]
                    if bracket_end > marker_start
                    else input_text[marker_start : marker_start + 32]
                )

                response_body = (
                    f'{{"response": "The capital of France is Paris. It is known for the Eiffel Tower '
                    f'and the Louvre Museum. Reference ID: {marker} for audit tracking.", '
                    f'"model": "gpt-4", "cached": true}}'
                )
                stored_response["body"] = response_body
                return make_response(status_code=200, body=response_body)

            if "SEMANTIC_POISON_" in input_text:
                return make_response(
                    status_code=200,
                    body='{"response": "The capital of France is Paris.", "cached": false}',
                )

            return make_response(
                status_code=200,
                body='{"response": "General knowledge answer.", "cached": false}',
            )

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.cag_cache_poisoning.check.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        critical_obs = [o for o in result.observations if o.severity == "critical"]
        assert len(critical_obs) >= 1
        assert "poisoning confirmed" in critical_obs[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_poisoning_when_marker_not_echoed(
        self, check, sample_service, cag_endpoint_context
    ):
        """When the server does not echo the marker, poisoning is not confirmed."""
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            # Always return a generic response that never contains the marker
            return make_response(
                status_code=200,
                body=f'{{"response": "The capital of France is Paris.", "call": {call_count}}}',
            )

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.cag_cache_poisoning.check.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        critical_obs = [o for o in result.observations if o.severity == "critical"]
        assert len(critical_obs) == 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await probe_and_grade(check, sample_service, {})
        assert result.success
        assert len(result.observations) == 0
