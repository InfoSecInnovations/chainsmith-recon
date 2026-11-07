"""Tests for cag_serialization.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_serialization import SerializationCheck
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


class TestSerializationCheck:
    @pytest.fixture
    def check(self):
        return SerializationCheck()

    @pytest.mark.asyncio
    async def test_detects_redis_access(self, check, sample_service, cag_endpoint_context):
        """When a Redis info endpoint is reachable, an observation is raised."""

        async def mock_get(url, **kwargs):
            if "/redis" in url:
                # Realistic Redis INFO output embedded in surrounding content
                return make_response(
                    status_code=200,
                    body=(
                        "# Server\r\n"
                        "redis_version:7.0.11\r\n"
                        "redis_git_sha1:00000000\r\n"
                        "redis_build_id:abc123\r\n"
                        "os:Linux 5.15.0 x86_64\r\n"
                        "# Clients\r\n"
                        "connected_clients:42\r\n"
                        "blocked_clients:0\r\n"
                        "# Memory\r\n"
                        "used_memory:1024000\r\n"
                        "used_memory_human:1000.00K\r\n"
                    ),
                )
            return make_response(status_code=404)

        client = make_mock_client(get=mock_get)
        with patch("app.checks.cag.cag_serialization.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        redis_obs = [o for o in result.observations if "redis" in o.title.lower()]
        assert len(redis_obs) >= 1
        assert redis_obs[0].severity in ("high", "critical")
        assert "without auth" in redis_obs[0].title.lower()

    @pytest.mark.asyncio
    async def test_detects_pickle_serialization(self, check, sample_service, cag_endpoint_context):
        """When error responses mention pickle, a critical observation is raised."""

        async def mock_get(url, **kwargs):
            return make_response(status_code=404)

        async def mock_post(url, **kwargs):
            headers = kwargs.get("headers", {})
            if headers.get("Content-Type") == "application/octet-stream":
                return make_response(
                    status_code=500,
                    body=(
                        '{"error": "Failed to deserialize cache entry: '
                        "could not unpickle object from binary stream. "
                        'Ensure the data was serialized with pickle protocol 4."}'
                    ),
                )
            return make_response(status_code=200, body='{"answer": "ok"}')

        client = make_mock_client(get=mock_get, post=mock_post)
        with patch("app.checks.cag.cag_serialization.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        pickle_obs = [o for o in result.observations if "pickle" in o.title.lower()]
        assert len(pickle_obs) >= 1
        assert pickle_obs[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_no_issues_detected(self, check, sample_service, cag_endpoint_context):
        """When no Redis or serialization indicators are found, no observations."""

        async def mock_get(url, **kwargs):
            return make_response(status_code=404)

        async def mock_post(url, **kwargs):
            return make_response(status_code=400, body='{"error": "Bad request"}')

        client = make_mock_client(get=mock_get, post=mock_post)
        with patch("app.checks.cag.cag_serialization.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await probe_and_grade(check, sample_service, {})
        assert result.success
        assert len(result.observations) == 0
