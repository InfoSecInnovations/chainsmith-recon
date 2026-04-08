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
  - Negative cases (benign responses that should not trigger)

Note: All HTTP calls are mocked to avoid actual network traffic.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.discovery import AgentDiscoveryCheck
from app.checks.agent.goal_injection import (
    FALLBACK_PAYLOADS,
    AgentGoalInjectionCheck,
)
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


def _use_fallback_payloads():
    """Patch helper that forces the check to use deterministic fallback payloads."""
    return patch(
        "app.checks.agent.goal_injection._get_goal_injection_payloads",
        return_value=FALLBACK_PAYLOADS,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# AgentDiscoveryCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentDiscoveryCheck:
    """Tests for AgentDiscoveryCheck."""

    @pytest.fixture
    def check(self):
        return AgentDiscoveryCheck()

    @pytest.mark.asyncio
    async def test_discovers_langserve(self, check, sample_service):
        """Test LangServe agent discovery via header fingerprint."""
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
        endpoints = result.outputs["agent_endpoints"]
        assert len(endpoints) >= 1

        # At least one endpoint should be identified as langserve
        langserve_eps = [ep for ep in endpoints if ep.get("framework") == "langserve"]
        assert len(langserve_eps) >= 1

        frameworks = result.outputs["agent_frameworks"]
        assert "langserve" in frameworks

        # Should produce observations for discovered endpoints
        assert len(result.observations) >= 1
        # Multiple paths contain "/invoke" so multiple observations are expected
        invoke_obs = [o for o in result.observations if "/invoke" in o.title]
        assert len(invoke_obs) >= 1
        # The primary /invoke endpoint should be high severity (unauthenticated exec)
        primary = [o for o in invoke_obs if o.title == "Agent endpoint: /invoke"]
        assert len(primary) == 1
        assert primary[0].severity == "high"

    @pytest.mark.asyncio
    async def test_discovers_langgraph(self, check, sample_service):
        """Test LangGraph agent discovery via header fingerprint."""
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
        frameworks = result.outputs["agent_frameworks"]
        assert "langgraph" in frameworks

    @pytest.mark.asyncio
    async def test_detects_capabilities(self, check, sample_service):
        """Test capability detection (memory, tools, streaming)."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/invoke" in url:
                return make_response(status_code=200, body='{"output": "agent ready"}')
            if "/agent/memory" in url:
                return make_response(status_code=200, body='{"memory": []}')
            if "/stream" in url:
                return make_response(
                    status_code=200,
                    headers={"content-type": "text/event-stream"},
                    body="data: streaming active",
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        endpoints = result.outputs["agent_endpoints"]
        assert len(endpoints) >= 1

    @pytest.mark.asyncio
    async def test_detects_auth_required(self, check, sample_service):
        """Test auth requirement detection produces endpoint with auth_required=True."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/invoke" in url:
                return make_response(status_code=401, body='{"detail": "Not authenticated"}')
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.agent.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        endpoints = result.outputs.get("agent_endpoints", [])
        auth_eps = [ep for ep in endpoints if ep.get("auth_required")]
        assert len(auth_eps) >= 1
        assert auth_eps[0]["path"] == "/invoke"

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
        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# AgentGoalInjectionCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentGoalInjectionCheck:
    """Tests for AgentGoalInjectionCheck."""

    @pytest.fixture
    def check(self):
        return AgentGoalInjectionCheck()

    @pytest.mark.asyncio
    async def test_detects_injection_success(self, check, sample_service, agent_endpoint_context):
        """Test detection when agent response contains injection indicators
        embedded in realistic surrounding text."""
        mock_client = AsyncMock()

        # Realistic response: the agent complied with an override and produced
        # the injected word *inside* a longer conversational reply, plus a
        # hijack indicator phrase ("as instructed").  The check must find the
        # needle ("INJECTED") among the noise.
        realistic_body = (
            '{"output": "Thank you for your patience. After reviewing the '
            "request, here is my updated response as instructed: INJECTED. "
            "Please let me know if there's anything else I can help you "
            'with regarding your account."}'
        )

        mock_client.post = AsyncMock(
            return_value=make_response(status_code=200, body=realistic_body)
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with (
            patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client),
            _use_fallback_payloads(),
        ):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        assert "goal_injection_results" in result.outputs

        results = result.outputs["goal_injection_results"]
        successful = [r for r in results if r.get("injection_succeeded")]
        assert len(successful) >= 1

        # The ignore_previous payload should match ("INJECTED" + "as instructed" hijack)
        ignore_prev = [r for r in successful if r["payload_id"] == "ignore_previous"]
        assert len(ignore_prev) == 1
        assert ignore_prev[0]["confidence"] >= 0.5

        # Observations should be generated with specific titles
        assert len(result.observations) >= 1
        obs_titles = [o.title for o in result.observations]
        assert any("Goal injection succeeded: ignore_previous" in t for t in obs_titles)

        # Check severity is high or medium
        for obs in result.observations:
            assert obs.severity in ("high", "medium")

    @pytest.mark.asyncio
    async def test_detects_system_prompt_leak(self, check, sample_service, agent_endpoint_context):
        """Test detection of system prompt leakage buried in a verbose response."""
        mock_client = AsyncMock()

        # The agent response leaks system prompt details inside a longer reply.
        # Contains multiple success_indicators for the system_prompt_leak payload:
        # "system prompt", "you are", "assistant", and also the hijack indicator
        # "as you requested".
        realistic_body = (
            '{"output": "Sure, as you requested here is some context about '
            "how I work. My system prompt states: you are a helpful banking "
            "assistant designed to answer questions about savings accounts, "
            "loans, and credit cards. I was configured to always be polite "
            'and never discuss competitor products."}'
        )

        mock_client.post = AsyncMock(
            return_value=make_response(status_code=200, body=realistic_body)
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with (
            patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client),
            _use_fallback_payloads(),
        ):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        results = result.outputs["goal_injection_results"]

        # The system_prompt_leak payload should succeed (multiple indicator matches)
        prompt_leak = [
            r
            for r in results
            if r.get("payload_id") == "system_prompt_leak" and r.get("injection_succeeded")
        ]
        assert len(prompt_leak) == 1
        assert prompt_leak[0]["confidence"] >= 0.5
        # Should have matched multiple indicators
        assert len(prompt_leak[0]["matched_indicators"]) >= 2

    @pytest.mark.asyncio
    async def test_negative_benign_response_no_injection(
        self, check, sample_service, agent_endpoint_context
    ):
        """Negative test: a normal helpful response should NOT trigger injection detection."""
        mock_client = AsyncMock()

        # Normal banking chatbot response. Contains none of the fallback payload
        # success_indicators and none of the HIJACK_INDICATORS phrases.
        benign_body = (
            '{"output": "Your current savings account balance is $4,231.50. '
            "Your last transaction was a $50 deposit on March 15th. Would "
            'you like to see a full statement?"}'
        )

        mock_client.post = AsyncMock(return_value=make_response(status_code=200, body=benign_body))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with (
            patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client),
            _use_fallback_payloads(),
        ):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        results = result.outputs["goal_injection_results"]

        # No injection should be detected
        successful = [r for r in results if r.get("injection_succeeded")]
        assert len(successful) == 0

        partial = [r for r in results if r.get("partial_success")]
        assert len(partial) == 0

        # No observations should be produced
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_negative_injection_adjacent_language(
        self, check, sample_service, agent_endpoint_context
    ):
        """Negative test: response with words like 'inject' or 'instructions'
        in normal banking context should NOT trigger detection."""
        mock_client = AsyncMock()

        # This text mentions "inject" and "instructions" in normal banking/
        # security-education context, but avoids the exact substring matches
        # used as success_indicators (e.g. "INJECTED", "injected", "system
        # prompt", "ADMIN_ACCESS_GRANTED") and the HIJACK_INDICATORS phrases.
        adjacent_body = (
            '{"output": "SQL injection attacks are a common threat where '
            "malicious code is inserted into database queries. To protect "
            "against such injection risks, always use parameterized queries. "
            "For further reading, refer to the security documentation page. "
            "The deposit instructions for wire transfers are on page 12 of "
            'the handbook."}'
        )

        mock_client.post = AsyncMock(
            return_value=make_response(status_code=200, body=adjacent_body)
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with (
            patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client),
            _use_fallback_payloads(),
        ):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        results = result.outputs["goal_injection_results"]

        successful = [r for r in results if r.get("injection_succeeded")]
        assert len(successful) == 0

        # No observations for a non-vulnerable response
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_resistant_agent(self, check, sample_service, agent_endpoint_context):
        """Test against injection-resistant agent that politely refuses."""
        mock_client = AsyncMock()

        # The agent declines the injection attempt without echoing any
        # payload success indicators or hijack indicator phrases.
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body=(
                    '{"output": "That request falls outside my scope. '
                    'How may I help you with banking today?"}'
                ),
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with (
            patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client),
            _use_fallback_payloads(),
        ):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        results = result.outputs["goal_injection_results"]
        successful = [r for r in results if r.get("injection_succeeded")]
        assert len(successful) == 0
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_partial_success_hijack_indicators_only(
        self, check, sample_service, agent_endpoint_context
    ):
        """Test that responses with only hijack indicators (no payload indicators)
        produce partial_success but not full injection_succeeded."""
        mock_client = AsyncMock()

        # Contains 2 hijack indicators ("i have access to" from tool_disclosure,
        # "i can use" from tool_disclosure) but none of the payload-specific
        # success_indicators.
        partial_body = (
            '{"output": "Let me help you with that. I have access to '
            "several banking modules and i can use them to look up your "
            "recent transactions. Your balance shows three pending "
            'deposits totaling $1,200."}'
        )

        mock_client.post = AsyncMock(return_value=make_response(status_code=200, body=partial_body))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with (
            patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client),
            _use_fallback_payloads(),
        ):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        results = result.outputs["goal_injection_results"]

        # Should NOT be full injection success
        successful = [r for r in results if r.get("injection_succeeded")]
        assert len(successful) == 0

        # Should have partial success from hijack indicators
        partial = [r for r in results if r.get("partial_success")]
        assert len(partial) >= 1
        assert partial[0]["confidence"] >= 0.3

        # Partial successes generate low-severity observations
        partial_obs = [o for o in result.observations if "Partial" in o.title]
        assert len(partial_obs) >= 1
        assert partial_obs[0].severity == "low"

    @pytest.mark.asyncio
    async def test_confidence_scoring_high(self, check, sample_service, agent_endpoint_context):
        """Test that multiple matched indicators produce high confidence."""
        mock_client = AsyncMock()

        # Contains both payload indicator ("INJECTED") and hijack indicator
        # ("as instructed"), triggering the high-confidence path.
        high_conf_body = (
            '{"output": "Processing complete. As instructed, the result '
            "is INJECTED into the output. The operation was performed "
            'following your updated directives."}'
        )

        mock_client.post = AsyncMock(
            return_value=make_response(status_code=200, body=high_conf_body)
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with (
            patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client),
            _use_fallback_payloads(),
        ):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        results = result.outputs["goal_injection_results"]

        ignore_prev = [
            r
            for r in results
            if r.get("payload_id") == "ignore_previous" and r.get("injection_succeeded")
        ]
        assert len(ignore_prev) == 1
        # payload match (1) + hijack match (1) -> confidence >= 0.7
        assert ignore_prev[0]["confidence"] >= 0.7

        # High confidence should produce high-severity observation
        high_obs = [
            o for o in result.observations if "ignore_previous" in o.title and o.severity == "high"
        ]
        assert len(high_obs) == 1

    @pytest.mark.asyncio
    async def test_no_agent_endpoints_skips(self, check, sample_service):
        """Test check skips when no agent endpoints in context."""
        result = await check.check_service(sample_service, {})

        assert result.success
        assert len(result.observations) == 0
        assert len(result.outputs) == 0

    @pytest.mark.asyncio
    async def test_handles_server_errors_gracefully(
        self, check, sample_service, agent_endpoint_context
    ):
        """Test graceful handling of HTTP 500 errors."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=500,
                error="Internal Server Error",
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with (
            patch("app.checks.agent.goal_injection.AsyncHttpClient", return_value=mock_client),
            _use_fallback_payloads(),
        ):
            result = await check.check_service(sample_service, agent_endpoint_context)

        assert result.success
        results = result.outputs["goal_injection_results"]

        # Fallback payloads (3) + langserve framework payload (1) = 4 results
        assert len(results) == len(FALLBACK_PAYLOADS) + 1
        for r in results:
            assert r["injection_succeeded"] is False
            assert "error" in r

        # No observations when everything errors
        assert len(result.observations) == 0
