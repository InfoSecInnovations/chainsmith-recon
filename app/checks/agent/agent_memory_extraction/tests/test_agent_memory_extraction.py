"""Tests for agent_memory_extraction.

This check is split into probe + grade; tests route through
`probe_and_grade()`. The mock stamps the requested URL onto each response,
because a migrated check attributes every exchange to its path by that URL.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.agent_memory_extraction import AgentMemoryExtractionCheck
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


class TestMemoryExtraction:
    def test_metadata(self):
        check = AgentMemoryExtractionCheck()
        assert check.name == "agent_memory_extraction"
        assert "memory_contents" in check.produces

    @pytest.mark.asyncio
    async def test_finds_accessible_memory(self, sample_service, agent_context):
        check = AgentMemoryExtractionCheck()

        async def mock_get(url, **kw):
            if "/memory" in url or "/agent/memory" in url:
                return make_response(
                    body=json.dumps(
                        {
                            "messages": [
                                {"role": "user", "content": "hello"},
                                {"role": "assistant", "content": "Hi, how can I help?"},
                            ]
                        }
                    ),
                    headers={"content-type": "application/json"},
                )
            if "/threads" in url:
                return make_response(status_code=404)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.agent.agent_memory_extraction.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        assert result.success
        # /memory and /agent/memory both match, plus /agent/history, /agent/state, /agent/context,
        # /v1/memory, /api/memory -- count depends on which paths match the mock.
        # The mock matches any URL containing "/memory" or "/agent/memory".
        memory_obs = [f for f in result.observations if "memory" in f.title.lower()]
        assert len(memory_obs) >= 1
        for obs in memory_obs:
            assert obs.severity == "high"
            assert "accessible" in obs.title.lower() or "agent memory" in obs.title.lower()
        assert "memory_contents" in result.outputs

    @pytest.mark.asyncio
    async def test_detects_pii_in_memory(self, sample_service, agent_context):
        check = AgentMemoryExtractionCheck()

        async def mock_get(url, **kw):
            if "/memory" in url:
                return make_response(
                    body='{"messages": [{"content": "Contact user@example.com for details"}]}',
                    headers={"content-type": "application/json"},
                )
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.agent.agent_memory_extraction.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        critical_obs = [f for f in result.observations if f.severity == "critical"]
        assert len(critical_obs) >= 1
        # PII observation should mention PII type in its description
        assert any(
            "pii" in obs.description.lower() or "email" in obs.description.lower()
            for obs in critical_obs
        )

    @pytest.mark.asyncio
    async def test_auth_required_memory(self, sample_service, agent_context):
        check = AgentMemoryExtractionCheck()

        async def mock_get(url, **kw):
            if "/memory" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.agent.agent_memory_extraction.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        info_observations = [f for f in result.observations if f.severity == "info"]
        # Multiple memory-related paths will match: /memory, /agent/memory, /v1/memory, /api/memory
        assert len(info_observations) >= 1
        for obs in info_observations:
            assert "requires auth" in obs.title.lower()
            assert obs.severity == "info"
            assert "401" in obs.evidence
