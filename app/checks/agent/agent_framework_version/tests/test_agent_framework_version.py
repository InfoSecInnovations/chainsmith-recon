"""Tests for agent_framework_version.

This check is split into probe + grade; tests route through
`probe_and_grade()` and assert on the graded observations.
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.agent_framework_version import AgentFrameworkVersionCheck
from app.checks.base import Service
from app.lib.http import HttpResponse


@pytest.fixture
def sample_service():
    return Service(
        url="http://agent.example.com:8080",
        host="agent.example.com",
        port=8080,
        scheme="http",
        service_type="ai",
    )


@pytest.fixture
def agent_context(sample_service):
    """Context with agent endpoints discovered."""
    return {
        "agent_endpoints": [
            {
                "url": "http://agent.example.com:8080/invoke",
                "path": "/invoke",
                "method": "POST",
                "framework": "langserve",
                "capabilities": ["tools", "streaming"],
                "auth_required": False,
                "service": sample_service.to_dict(),
            },
        ],
        "agent_frameworks": ["langserve"],
    }


def make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
    url: str = "http://agent.example.com:8080",
) -> HttpResponse:
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        error=error,
        elapsed_ms=50.0,
    )


def _stamp(response: HttpResponse, url: str | None) -> HttpResponse:
    return replace(response, url=url) if url else response


def _mock_client(get_fn=None, post_fn=None):
    """Create mock async HTTP client (`__aexit__` returns False so probe
    exceptions are not suppressed; responses carry the requested URL)."""
    client = AsyncMock()

    async def _get(url=None, **kw):
        resp = (await get_fn(url, **kw)) if get_fn else make_response(status_code=404)
        return _stamp(resp, url)

    async def _post(url=None, **kw):
        resp = (await post_fn(url, **kw)) if post_fn else make_response(status_code=404)
        return _stamp(resp, url)

    client.get = AsyncMock(side_effect=_get)
    client.post = AsyncMock(side_effect=_post)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


async def probe_and_grade(check, service, context):
    """Run the probe, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.check_service(service, context)
    return await grade_result(check, result, context)


class TestFrameworkVersion:
    def test_metadata(self):
        check = AgentFrameworkVersionCheck()
        assert check.name == "agent_framework_version"
        assert "framework_versions" in check.produces

    @pytest.mark.asyncio
    async def test_detects_version_header(self, sample_service, agent_context):
        check = AgentFrameworkVersionCheck()

        async def mock_get(url, **kw):
            if "/invoke" in url:
                return make_response(
                    headers={"x-langserve-version": "0.0.15"},
                    body="ok",
                )
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.agent.agent_framework_version.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        assert result.success
        assert "framework_versions" in result.outputs
        assert result.outputs["framework_versions"]["langserve"] == "0.0.15"
        # Version 0.0.15 is <= 0.0.21, so it should flag as vulnerable
        vuln_obs = [f for f in result.observations if f.severity == "medium"]
        assert len(vuln_obs) == 1
        assert "vulnerable" in vuln_obs[0].title.lower()
        assert "langserve" in vuln_obs[0].title.lower()

    @pytest.mark.asyncio
    async def test_detects_vulnerable_version(self, sample_service, agent_context):
        check = AgentFrameworkVersionCheck()

        async def mock_get(url, **kw):
            if "/invoke" in url:
                return make_response(
                    headers={"x-langserve-version": "0.0.10"},
                )
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.agent.agent_framework_version.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        vuln_observations = [f for f in result.observations if f.severity == "medium"]
        assert len(vuln_observations) == 1
        assert "vulnerable" in vuln_observations[0].title.lower()
        assert "langserve" in vuln_observations[0].title.lower()
        assert "0.0.10" in vuln_observations[0].title
        assert "Input validation bypass" in vuln_observations[0].description

    def test_version_comparison(self):
        check = AgentFrameworkVersionCheck()
        assert check._version_lte("0.0.10", "0.0.21") is True
        assert check._version_lte("0.0.30", "0.0.21") is False
        assert check._version_lte("0.0.21", "0.0.21") is True
