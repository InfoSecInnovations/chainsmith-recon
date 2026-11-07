"""Tests for cag_side_channel.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions. Timing is now driven by
each mock response's `elapsed_ms` (what the probe records on the exchange and
`grade()` reads back), not by patching `time.time` (§0.12).
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_side_channel import SideChannelCheck
from app.checks.cag.cag_side_channel.check import BASELINE_PREFIX
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
    """Create a standard mock HTTP client.

    `__aexit__` returns False so a probe exception is not suppressed (§0.14).
    """
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


class TestSideChannelCheck:
    @pytest.fixture
    def check(self):
        return SideChannelCheck()

    @pytest.mark.asyncio
    async def test_detects_timing_side_channel(self, check, sample_service, cag_endpoint_context):
        """When sensitive topic queries are faster than baseline, cache hits indicate side channel.

        Baseline queries answer at ~500ms; every sensitive-topic query answers at
        ~20ms (well under the 250ms cache-hit threshold), so each topic reads as a
        cache hit — recovered from each response's recorded `elapsed_ms`.
        """

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            query = body.get("input", "")
            if BASELINE_PREFIX in query:
                elapsed = 500.0  # baseline: cold, slow
            else:
                elapsed = 20.0  # sensitive topic: fast -> cache hit
            return _stamp(
                make_response(
                    status_code=200,
                    body='{"response": "Here is some information about your query."}',
                    elapsed_ms=elapsed,
                ),
                url,
            )

        client = make_mock_client(post=AsyncMock(side_effect=mock_post))
        with patch("app.checks.cag.cag_side_channel.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) >= 1
        obs = result.observations[0]
        assert obs.severity in ("medium", "low")
        assert "side-channel" in obs.title.lower() or "timing" in obs.title.lower()

    @pytest.mark.asyncio
    async def test_no_side_channel_when_endpoint_errors(
        self, check, sample_service, cag_endpoint_context
    ):
        """When all baseline requests error, no side channel analysis is possible."""

        async def mock_post(url, **kwargs):
            return _stamp(
                make_response(status_code=500, body='{"error": "server error"}', error="500"),
                url,
            )

        client = make_mock_client(post=AsyncMock(side_effect=mock_post))
        with patch("app.checks.cag.cag_side_channel.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        # No observations when baseline fails
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await probe_and_grade(check, sample_service, {})
        assert result.success
        assert len(result.observations) == 0
