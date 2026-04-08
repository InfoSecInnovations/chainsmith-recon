"""Tests for agent discovery & fingerprinting checks (multi-agent detection, framework version, memory extraction)."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.framework_version import AgentFrameworkVersionCheck
from app.checks.agent.memory_extraction import AgentMemoryExtractionCheck
from app.checks.agent.multi_agent_detection import AgentMultiAgentDetectionCheck
from app.checks.base import Service
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


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
) -> HttpResponse:
    return HttpResponse(
        url="http://agent.example.com:8080",
        status_code=status_code,
        headers=headers or {},
        body=body,
        error=error,
        elapsed_ms=50.0,
    )


def _mock_client(get_fn=None, post_fn=None):
    """Create mock async HTTP client."""
    client = AsyncMock()
    client.get = get_fn or AsyncMock(return_value=make_response(status_code=404))
    client.post = post_fn or AsyncMock(return_value=make_response(status_code=404))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock()
    return client


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 1: Discovery & Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════════


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

        with patch("app.checks.agent.multi_agent_detection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

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

        with patch("app.checks.agent.multi_agent_detection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

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

        with patch("app.checks.agent.multi_agent_detection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

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

        with patch("app.checks.agent.multi_agent_detection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        assert result.success
        assert len(result.observations) == 0
        assert "multi_agent_topology" not in result.outputs


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

        with patch("app.checks.agent.framework_version.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

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

        with patch("app.checks.agent.framework_version.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

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

        with patch("app.checks.agent.memory_extraction.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

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

        with patch("app.checks.agent.memory_extraction.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

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

        with patch("app.checks.agent.memory_extraction.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        info_observations = [f for f in result.observations if f.severity == "info"]
        # Multiple memory-related paths will match: /memory, /agent/memory, /v1/memory, /api/memory
        assert len(info_observations) >= 1
        for obs in info_observations:
            assert "requires auth" in obs.title.lower()
            assert obs.severity == "info"
            assert "401" in obs.evidence
