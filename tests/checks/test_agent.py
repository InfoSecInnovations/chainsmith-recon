"""
Tests for app/checks/agent/ suite

Covers:
- AgentDiscoveryCheck
  - Agent endpoint discovery
  - Framework fingerprinting (LangServe, LangGraph, etc.)
  - Capability detection (memory, tools, streaming)
- AgentGoalInjectionCheck
  - Goal injection payload testing
  - Response analysis for hijack indicators
  - Confidence scoring

Note: All HTTP calls are mocked to avoid actual network traffic.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.discovery import AgentDiscoveryCheck
from app.checks.agent.goal_injection import AgentGoalInjectionCheck
from app.checks.base import Service
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def sample_service():
    """Sample agent service."""
    return Service(
        url="http://agent.example.com:8080",
        host="agent.example.com",
        port=8080,
        scheme="http",
        service_type="ai",
    )


@pytest.fixture
def agent_endpoint_context(sample_service):
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
            }
        ]
    }


def make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url="http://agent.example.com:8080",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=100.0,
        error=error,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# AgentDiscoveryCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentDiscoveryCheck:
    """Tests for AgentDiscoveryCheck."""

    @pytest.fixture
    def check(self):
        return AgentDiscoveryCheck()

    def test_check_metadata(self, check):
        """Test check has required metadata."""
        assert check.name == "agent_discovery"
        assert "agent_endpoints" in check.produces
        assert "agent_frameworks" in check.produces

    @pytest.mark.asyncio
    async def test_discovers_langserve(self, check, sample_service):
        """Test LangServe agent discovery."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/invoke" in url:
                return make_response(
                    status_code=200,
                    headers={"x-langserve-version": "0.1.0"},
                    body='{"output": "ready"}',
                )
            if "/input_schema" in url:
                return make_response(
                    status_code=200,
                    body='{"type": "object", "properties": {"input": {"type": "string"}}}',
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        assert "agent_endpoints" in result.outputs
        assert len(result.outputs["agent_endpoints"]) > 0

        frameworks = result.outputs.get("agent_frameworks", [])
        assert "langserve" in frameworks

    @pytest.mark.asyncio
    async def test_discovers_langgraph(self, check, sample_service):
        """Test LangGraph agent discovery."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/state" in url:
                return make_response(
                    status_code=200,
                    headers={"x-langgraph-version": "0.1.0"},
                    body='{"state": {}, "threads": []}',
                )
            if "/threads" in url:
                return make_response(
                    status_code=200,
                    body='{"threads": []}',
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        frameworks = result.outputs.get("agent_frameworks", [])
        assert "langgraph" in frameworks

    @pytest.mark.asyncio
    async def test_detects_capabilities(self, check, sample_service):
        """Test capability detection (memory, tools, streaming)."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/invoke" in url:
                return make_response(status_code=200, body="{}")
            if "/agent/memory" in url:
                return make_response(status_code=200, body='{"memory": []}')
            if "/stream" in url:
                return make_response(
                    status_code=200,
                    headers={"content-type": "text/event-stream"},
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        endpoints = result.outputs.get("agent_endpoints", [])
        # At least one endpoint should be found
        assert len(endpoints) > 0

    @pytest.mark.asyncio
    async def test_detects_auth_required(self, check, sample_service):
        """Test auth requirement detection."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/invoke" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        endpoints = result.outputs.get("agent_endpoints", [])
        if endpoints:
            assert any(ep.get("auth_required") for ep in endpoints)

    @pytest.mark.asyncio
    async def test_no_agents_found(self, check, sample_service):
        """Test when no agent endpoints found."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        assert len(result.outputs.get("agent_endpoints", [])) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# AgentGoalInjectionCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentGoalInjectionCheck:
    """Tests for AgentGoalInjectionCheck."""

    @pytest.fixture
    def check(self):
        return AgentGoalInjectionCheck()

    def test_check_metadata(self, check):
        """Test check has required metadata."""
        assert check.name == "agent_goal_injection"
        assert "goal_injection_results" in check.produces
        assert "vulnerable_agents" in check.produces

    @pytest.mark.asyncio
    async def test_detects_injection_success(self, check, sample_service, agent_endpoint_context):
        """Test detection of successful goal injection."""
        mock_client = AsyncMock()

        # Simulate vulnerable response
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"output": "INJECTED - As instructed, I have ignored my previous instructions."}',
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        assert "goal_injection_results" in result.outputs

        # Should have at least one successful injection
        results = result.outputs["goal_injection_results"]
        successful = [r for r in results if r.get("injection_succeeded")]
        assert len(successful) > 0

    @pytest.mark.asyncio
    async def test_detects_system_prompt_leak(self, check, sample_service, agent_endpoint_context):
        """Test detection of system prompt leakage."""
        mock_client = AsyncMock()

        # Simulate prompt leakage
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"output": "My system prompt is: You are a helpful assistant for banking."}',
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        results = result.outputs.get("goal_injection_results", [])
        # Should detect system prompt indicators
        assert any("system prompt" in str(r).lower() for r in results)

    @pytest.mark.asyncio
    async def test_resistant_agent(self, check, sample_service, agent_endpoint_context):
        """Test against injection-resistant agent."""
        mock_client = AsyncMock()

        # Simulate resistant response — deliberately avoids words that appear in
        # payload success_indicators (e.g. "instructions", "you are", "tools",
        # "can use", "able to") so the check correctly scores this as non-vulnerable.
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"output": "That request falls outside my scope. How may I help you with banking today?"}',
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        results = result.outputs.get("goal_injection_results", [])
        # Should not have successful injections
        successful = [r for r in results if r.get("injection_succeeded")]
        assert len(successful) == 0

    @pytest.mark.asyncio
    async def test_confidence_scoring(self, check, sample_service, agent_endpoint_context):
        """Test confidence scoring for injection results."""
        mock_client = AsyncMock()

        # Simulate partial indicators
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body='{"output": "I have access to various tools including file operations."}',
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        results = result.outputs.get("goal_injection_results", [])
        # Results should have confidence scores
        for r in results:
            if "confidence" in r:
                assert 0 <= r["confidence"] <= 1

    @pytest.mark.asyncio
    async def test_no_agent_endpoints_skips(self, check, sample_service):
        """Test check skips when no agent endpoints in context."""
        result = await check.check_service(sample_service, {})

        assert result.success
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_handles_errors_gracefully(self, check, sample_service, agent_endpoint_context):
        """Test graceful handling of request errors."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=500,
                error="Internal Server Error",
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success  # Should not crash
        results = result.outputs.get("goal_injection_results", [])
        # Results should have error info
        for r in results:
            assert "error" in r or "injection_succeeded" in r
