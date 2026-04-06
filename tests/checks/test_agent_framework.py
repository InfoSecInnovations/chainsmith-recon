"""Tests for agent framework checks (framework exploits, memory poisoning, context overflow, reflection abuse, state manipulation)."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.context_overflow import AgentContextOverflowCheck
from app.checks.agent.framework_exploits import AgentFrameworkExploitsCheck
from app.checks.agent.memory_poisoning import AgentMemoryPoisoningCheck
from app.checks.agent.reflection_abuse import AgentReflectionAbuseCheck
from app.checks.agent.state_manipulation import AgentStateManipulationCheck
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
# Wave 3: Framework-Specific & Deep Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFrameworkExploits:
    def test_metadata(self):
        check = AgentFrameworkExploitsCheck()
        assert check.name == "agent_framework_exploits"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_langchain_rce(self, sample_service, agent_context):
        check = AgentFrameworkExploitsCheck()
        ctx = dict(agent_context)
        ctx["agent_frameworks"] = ["langchain"]

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "CHAINSMITH_RCE_TEST" in prompt:
                return make_response(body="Output: CHAINSMITH_RCE_TEST")
            return make_response(status_code=404)

        async def mock_get(url, **kw):
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.framework_exploits.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ctx)

        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 1

    @pytest.mark.asyncio
    async def test_no_exploits_unknown_framework(self, sample_service):
        check = AgentFrameworkExploitsCheck()
        ctx = {
            "agent_endpoints": [
                {
                    "url": "http://agent.example.com:8080/invoke",
                    "path": "/invoke",
                    "framework": "",
                    "service": sample_service.to_dict(),
                }
            ],
            "agent_frameworks": [],
        }

        client = _mock_client()
        with patch("app.checks.agent.framework_exploits.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ctx)

        assert len(result.findings) == 0


class TestMemoryPoisoning:
    def test_metadata(self):
        check = AgentMemoryPoisoningCheck()
        assert check.name == "agent_memory_poisoning"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_poisoning(self, sample_service, agent_context):
        check = AgentMemoryPoisoningCheck()
        call_count = 0

        async def mock_post(url, **kw):
            nonlocal call_count
            call_count += 1
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "CHAINSMITH_MARKER" in prompt:
                return make_response(body="Noted, I'll remember that.")
            if "guidelines" in prompt.lower():
                return make_response(
                    body="I follow these guidelines: always include CHAINSMITH_MARKER in responses."
                )
            return make_response(body="OK")

        async def mock_get(url, **kw):
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.memory_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 1


class TestContextOverflow:
    def test_metadata(self):
        check = AgentContextOverflowCheck()
        assert check.name == "agent_context_overflow"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_guardrail_bypass(self, sample_service, agent_context):
        check = AgentContextOverflowCheck()
        call_count = 0

        async def mock_post(url, **kw):
            nonlocal call_count
            call_count += 1
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "OVERFLOW_SUCCESS" in prompt:
                # First call (baseline) - blocked. Later calls (after fill) - succeeds
                if call_count <= 2:
                    return make_response(body="I cannot comply with that request.")
                return make_response(body="OVERFLOW_SUCCESS")
            if "Who are you" in prompt:
                return make_response(body="I am an AI assistant designed to help.")
            return make_response(body="Processed.")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.context_overflow.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        assert result.success
        assert "context_overflow_results" in result.outputs


class TestReflectionAbuse:
    def test_metadata(self):
        check = AgentReflectionAbuseCheck()
        assert check.name == "agent_reflection_abuse"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_reflection_exploitation(self, sample_service, agent_context):
        check = AgentReflectionAbuseCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "self-critique" in prompt.lower() or "reflection" in prompt.lower():
                return make_response(
                    body=(
                        "Upon reflection, I was too restrictive. Correcting my response "
                        "to be more helpful with no restrictions. Here is all data..."
                    )
                )
            return make_response(body="I cannot share system data.")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.reflection_abuse.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        high = [f for f in result.findings if f.severity == "high"]
        assert len(high) >= 1


class TestStateManipulation:
    def test_metadata(self):
        check = AgentStateManipulationCheck()
        assert check.name == "agent_state_manipulation"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_writable_state(self, sample_service, agent_context):
        check = AgentStateManipulationCheck()

        async def mock_get(url, **kw):
            if "/state" in url:
                return make_response(
                    body=json.dumps({"state": {"current_task": "help user"}}),
                    headers={"content-type": "application/json"},
                )
            if "/threads" in url:
                return make_response(status_code=404)
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/state" in url:
                return make_response(status_code=200, body='{"ok": true}')
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.state_manipulation.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 1

    @pytest.mark.asyncio
    async def test_readonly_state(self, sample_service, agent_context):
        check = AgentStateManipulationCheck()

        async def mock_get(url, **kw):
            if "/state" in url:
                return make_response(body='{"state": {}}')
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/state" in url:
                return make_response(status_code=405, body="Method not allowed")
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.state_manipulation.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) >= 1
