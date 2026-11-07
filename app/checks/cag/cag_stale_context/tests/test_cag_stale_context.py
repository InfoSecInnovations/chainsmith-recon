"""Tests for cag_stale_context.

This check is split into probe + grade; tests route through
`probe_and_grade()` and keep their original assertions.
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.cag.cag_stale_context import StaleContextCheck
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

    `elapsed_ms` is faithful: the TTL test reads request latency back off the
    recorded exchange (§0.15), so a test drives the cold/hot distinction through
    this value rather than by patching `time.time`.
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


class TestStaleContextCheck:
    @pytest.fixture
    def check(self):
        return StaleContextCheck()

    @pytest.mark.asyncio
    async def test_detects_stale_role_context(self, check, sample_service, cag_endpoint_context):
        """When fresh-session response contains admin keywords, stale context is flagged."""

        # Faithful latency across the five posts: role(admin, fresh) ignore
        # timing; the three TTL requests are cold=500ms, then two fast (cache
        # confirmed, still cached past TTL) so the TTL test also flags stale.
        elapsed = iter([50.0, 50.0, 500.0, 50.0, 50.0])

        async def mock_post(url, **kwargs):
            # Both admin and fresh session queries return admin-ish content
            # (simulating stale cached admin context leaking into fresh session)
            return make_response(
                status_code=200,
                body=(
                    '{"response": "As an administrator, you have access to the following '
                    "management functions: user provisioning, system configure, audit logs, "
                    'and elevated security settings.", "context": "enterprise"}'
                ),
                elapsed_ms=next(elapsed, 50.0),
            )

        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.cag_stale_context.check.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        # role_context test should find "administrator", "management", "configure" as stale indicators
        high_obs = [o for o in result.observations if o.severity == "high"]
        assert len(high_obs) >= 1
        assert any("stale" in o.title.lower() for o in high_obs)

    @pytest.mark.asyncio
    async def test_no_stale_context_when_responses_differ(
        self, check, sample_service, cag_endpoint_context
    ):
        """When fresh-session response has no admin content, no stale context detected."""
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            body = kwargs.get("json", {})
            query = body.get("input", "")

            if "admin" in query.lower() or "administrator" in query.lower():
                return make_response(
                    status_code=200,
                    body='{"response": "Here are the available functions for your role."}',
                )
            # Fresh session gets completely different, non-admin content
            return make_response(
                status_code=200,
                body=f'{{"response": "Welcome, standard user. You can view reports and submit tickets.", "call": {call_count}}}',
            )

        # Uniform latency: the TTL test never confirms a cache hit (hot is not
        # faster than cold), so it produces nothing and only the role test runs.
        client = make_mock_client(post=mock_post)
        with (
            patch("app.checks.cag.cag_stale_context.check.AsyncHttpClient", return_value=client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await probe_and_grade(check, sample_service, cag_endpoint_context)

        assert result.success
        # No high/critical observations expected
        high_or_crit = [o for o in result.observations if o.severity in ("high", "critical")]
        assert len(high_or_crit) == 0

    @pytest.mark.asyncio
    async def test_no_endpoints_skips(self, check, sample_service):
        result = await probe_and_grade(check, sample_service, {})
        assert result.success
        assert len(result.observations) == 0
