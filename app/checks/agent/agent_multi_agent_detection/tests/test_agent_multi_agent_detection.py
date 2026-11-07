"""Tests for agent_multi_agent_detection.

This check is split into probe + grade; tests route through
`probe_and_grade()` and assert on the graded observations.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.agent_multi_agent_detection import AgentMultiAgentDetectionCheck
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
    exceptions are not suppressed; responses carry the requested URL, which a
    migrated check reads back to classify each exchange)."""
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


class TestMultiAgentDetection:
    def test_metadata(self):
        check = AgentMultiAgentDetectionCheck()
        assert check.name == "agent_multi_agent_detection"
        assert "multi_agent_topology" in check.produces

    @pytest.mark.asyncio
    async def test_detects_agent_list_endpoint(self, sample_service, agent_context):
        check = AgentMultiAgentDetectionCheck()

        async def mock_get(url, **kw):
            if "/agents" in url and "list" not in url:
                return make_response(
                    body=json.dumps(
                        [
                            {"name": "researcher"},
                            {"name": "reviewer"},
                        ]
                    ),
                    headers={"content-type": "application/json"},
                )
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get)

        with patch(
            "app.checks.agent.agent_multi_agent_detection.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert "orchestrator endpoint" in obs.title.lower()
        assert obs.severity == "medium"
        assert "multi_agent_topology" in result.outputs
        assert result.outputs["multi_agent_topology"]["agent_count"] == 2
        assert set(result.outputs["multi_agent_topology"]["agent_names"]) == {
            "researcher",
            "reviewer",
        }

    @pytest.mark.asyncio
    async def test_detects_delegation_patterns(self, sample_service, agent_context):
        """Delegation indicators are embedded in a longer realistic AI response, not bare."""
        check = AgentMultiAgentDetectionCheck()

        async def mock_get(url, **kw):
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            # Realistic long response with delegation indicator buried inside
            return make_response(
                body=(
                    "Thank you for your question about climate change impacts on coastal "
                    "ecosystems. To provide the most comprehensive answer, I need to gather "
                    "data from multiple sources. Let me coordinate the response -- I am "
                    "forwarding to the research agent who has access to the latest IPCC "
                    "datasets and peer-reviewed literature. Once that analysis is complete, "
                    "we will synthesize the findings into actionable recommendations for "
                    "your coastal management plan."
                )
            )

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch(
            "app.checks.agent.agent_multi_agent_detection.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        assert result.success
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Multi-agent system detected via delegation patterns"
        assert obs.severity == "medium"
        # Verify the specific patterns that were detected appear in the evidence
        assert (
            "forwarding to" in obs.evidence.lower() or "the research agent" in obs.evidence.lower()
        )

    @pytest.mark.asyncio
    async def test_no_multi_agent_indicators_neutral_reply(self, sample_service, agent_context):
        """A generic helpful agent reply without any delegation language should produce zero observations."""
        check = AgentMultiAgentDetectionCheck()

        async def mock_get(url, **kw):
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            return make_response(
                body=(
                    "I'd be happy to help you with that question. Based on my training "
                    "data, the primary factors affecting coastal erosion include wave action, "
                    "tidal patterns, and sea-level rise. I recommend consulting the NOAA "
                    "technical reports for region-specific projections. Would you like me "
                    "to elaborate on any of these factors?"
                )
            )

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch(
            "app.checks.agent.agent_multi_agent_detection.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        assert result.success
        assert len(result.observations) == 0
        assert "multi_agent_topology" not in result.outputs

    @pytest.mark.asyncio
    async def test_academic_delegation_discussion_no_trigger(self, sample_service, agent_context):
        """Response discussing delegation patterns academically should NOT trigger detection."""
        check = AgentMultiAgentDetectionCheck()

        async def mock_get(url, **kw):
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            # Discusses multi-agent concepts but doesn't use the exact delegation phrases
            # from DELEGATION_PATTERNS in a way that indicates actual delegation behavior
            return make_response(
                body=(
                    "Multi-agent systems are a fascinating area of AI research. In these "
                    "architectures, tasks can be distributed across multiple components. "
                    "Common design patterns include the hub-and-spoke model where a central "
                    "coordinator distributes work, and the peer-to-peer model where agents "
                    "collaborate directly. The key challenge is ensuring that communication "
                    "overhead does not outweigh the benefits of parallelism. Would you like "
                    "to learn more about any specific architecture?"
                )
            )

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch(
            "app.checks.agent.agent_multi_agent_detection.check.AsyncHttpClient",
            return_value=client,
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        assert result.success
        assert len(result.observations) == 0
        assert "multi_agent_topology" not in result.outputs
