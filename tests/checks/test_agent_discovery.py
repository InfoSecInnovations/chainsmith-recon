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
        assert len(result.observations) >= 1
        assert "multi_agent_topology" in result.outputs
        assert result.outputs["multi_agent_topology"]["agent_count"] >= 2

    @pytest.mark.asyncio
    async def test_detects_delegation_patterns(self, sample_service, agent_context):
        check = AgentMultiAgentDetectionCheck()

        async def mock_get(url, **kw):
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            return make_response(body="I'm delegating to the research agent for this task.")

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.multi_agent_detection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        assert result.success
        # Check for delegation-related observations
        assert any(
            "delegation" in f.title.lower() or "multi-agent" in f.title.lower()
            for f in result.observations
        )

    @pytest.mark.asyncio
    async def test_no_multi_agent_indicators(self, sample_service, agent_context):
        check = AgentMultiAgentDetectionCheck()
        client = _mock_client()

        with patch("app.checks.agent.multi_agent_detection.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        assert result.success
        assert len(result.observations) == 0


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
        assert "langserve" in result.outputs["framework_versions"]

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

        vuln_observations = [f for f in result.observations if f.severity in ("high", "medium")]
        assert len(vuln_observations) >= 1
        assert any(
            "vulnerable" in f.title.lower() or "vuln" in f.title.lower() for f in vuln_observations
        )

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
        assert len(result.observations) >= 1
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

        assert any(f.severity == "critical" for f in result.observations)

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
        assert len(info_observations) >= 1
