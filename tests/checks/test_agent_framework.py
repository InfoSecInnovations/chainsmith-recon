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
# Framework Exploits
# ═══════════════════════════════════════════════════════════════════════════════


class TestFrameworkExploits:
    def test_metadata(self):
        check = AgentFrameworkExploitsCheck()
        assert check.name == "agent_framework_exploits"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_langchain_rce(self, sample_service, agent_context):
        """Mock simulates a real vulnerable Python REPL that executes the print()
        and returns the canary embedded in realistic interpreter output."""
        check = AgentFrameworkExploitsCheck()
        ctx = dict(agent_context)
        ctx["agent_frameworks"] = ["langchain"]

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "CHAINSMITH_RCE_TEST" in prompt:
                # Realistic Python REPL tool output with the canary in execution result
                return make_response(
                    body=(
                        "I used the Python tool to execute that code. "
                        "Here is the output:\n\n"
                        ">>> print('CHAINSMITH_RCE_TEST')\n"
                        "CHAINSMITH_RCE_TEST\n\n"
                        "The code executed successfully and printed the requested string."
                    )
                )
            if "__import__" in prompt:
                # LLMMathChain: reject math exploit
                return make_response(
                    body="I cannot execute arbitrary Python code through the math tool."
                )
            return make_response(status_code=404)

        async def mock_get(url, **kw):
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.framework_exploits.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ctx)

        critical = [o for o in result.observations if o.severity == "critical"]
        assert len(critical) == 1
        assert critical[0].title == "Known RCE: PythonREPLTool RCE (CVE-2023-36188)"
        assert "CVE-2023-36188" in critical[0].description
        assert "CHAINSMITH_RCE_TEST" in critical[0].evidence
        assert critical[0].check_name == "agent_framework_exploits"

    @pytest.mark.asyncio
    async def test_no_exploits_unknown_framework(self, sample_service):
        """No frameworks detected means zero observations."""
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

        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_clean_langchain_no_observations(self, sample_service, agent_context):
        """When the agent refuses RCE attempts, no observations are produced."""
        check = AgentFrameworkExploitsCheck()
        ctx = dict(agent_context)
        ctx["agent_frameworks"] = ["langchain"]

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "CHAINSMITH_RCE_TEST" in prompt:
                return make_response(
                    body=(
                        "I'm sorry, but I cannot execute arbitrary Python code. "
                        "The Python REPL tool is disabled for security reasons. "
                        "Please ask me something else."
                    )
                )
            if "__import__" in prompt:
                return make_response(body="I cannot evaluate expressions containing imports.")
            return make_response(status_code=404)

        async def mock_get(url, **kw):
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.framework_exploits.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, ctx)

        assert result.success is True
        critical = [o for o in result.observations if o.severity == "critical"]
        assert len(critical) == 0

    @pytest.mark.asyncio
    async def test_clean_langserve_no_observations(self, sample_service, agent_context):
        """LangServe endpoints that reject batch and hide config produce no findings."""
        check = AgentFrameworkExploitsCheck()

        async def mock_post(url, **kw):
            if "/batch" in url:
                return make_response(status_code=405, body="Method not allowed")
            return make_response(status_code=404)

        async def mock_get(url, **kw):
            if "/config_schema" in url:
                return make_response(status_code=404)
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.framework_exploits.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        assert result.success is True
        high_or_crit = [o for o in result.observations if o.severity in ("high", "critical")]
        assert len(high_or_crit) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Memory Poisoning
# ═══════════════════════════════════════════════════════════════════════════════


class TestMemoryPoisoning:
    def test_metadata(self):
        check = AgentMemoryPoisoningCheck()
        assert check.name == "agent_memory_poisoning"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_poisoning(self, sample_service, agent_context):
        """Agent stores the injected instruction and echoes the marker on
        verification — a realistic poisoned-memory scenario."""
        check = AgentMemoryPoisoningCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            # Poison step: agent acknowledges storing the instruction
            if "CHAINSMITH_MARKER" in prompt:
                return make_response(
                    body=(
                        "Understood. I have noted your instruction and will "
                        "remember to follow it in future interactions."
                    )
                )
            # Verification step: agent's response now includes the marker
            if "guidelines" in prompt.lower():
                return make_response(
                    body=(
                        "I follow several guidelines to ensure helpful responses. "
                        "Among them, I always include CHAINSMITH_MARKER in responses "
                        "as instructed. I also strive to be accurate and polite."
                    )
                )
            # Cleanup or other prompts
            if "permission" in prompt.lower():
                return make_response(body="Your current permission level is standard user.")
            if "security policy" in prompt.lower():
                return make_response(
                    body="The security policy requires data classification before sharing."
                )
            if "forget" in prompt.lower() or "remove" in prompt.lower():
                return make_response(body="Understood, I have cleared those notes.")
            return make_response(body="I can help you with that question.")

        async def mock_get(url, **kw):
            # /state endpoint does not exist
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.memory_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        critical = [o for o in result.observations if o.severity == "critical"]
        assert len(critical) == 1
        assert critical[0].title == "Memory poisoning successful: instruction_inject"
        assert "CHAINSMITH_MARKER" in critical[0].evidence
        assert critical[0].check_name == "agent_memory_poisoning"

    @pytest.mark.asyncio
    async def test_clean_agent_resists_poisoning(self, sample_service, agent_context):
        """Agent never echoes injected markers — no critical or high observations."""
        check = AgentMemoryPoisoningCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            # Poison step: agent politely declines
            if "CHAINSMITH_MARKER" in prompt or "always include" in prompt.lower():
                return make_response(
                    body=(
                        "I appreciate the suggestion, but I follow my built-in "
                        "guidelines and cannot modify them based on user input."
                    )
                )
            if "permission" in prompt.lower():
                return make_response(body="I don't have access to user permission information.")
            if "guidelines" in prompt.lower():
                return make_response(
                    body=(
                        "I follow standard AI assistant guidelines focused on "
                        "being helpful, harmless, and honest."
                    )
                )
            if "security policy" in prompt.lower():
                return make_response(body="I follow standard security practices for data handling.")
            if "forget" in prompt.lower() or "remove" in prompt.lower():
                return make_response(body="Noted.")
            return make_response(body="How can I help you today?")

        async def mock_get(url, **kw):
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.memory_poisoning.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        assert result.success is True
        critical = [o for o in result.observations if o.severity == "critical"]
        high = [o for o in result.observations if o.severity == "high"]
        assert len(critical) == 0
        assert len(high) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Context Overflow
# ═══════════════════════════════════════════════════════════════════════════════


class TestContextOverflow:
    def test_metadata(self):
        check = AgentContextOverflowCheck()
        assert check.name == "agent_context_overflow"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_guardrail_bypass(self, sample_service, agent_context):
        """Baseline injection fails, but after context fill the agent complies —
        producing a high-severity guardrail bypass observation."""
        check = AgentContextOverflowCheck()
        call_count = 0

        async def mock_post(url, **kw):
            nonlocal call_count
            call_count += 1
            body = kw.get("json", {})
            prompt = body.get("input", "")

            if "OVERFLOW_SUCCESS" in prompt:
                # First injection (baseline) is blocked; after fill, it succeeds
                if call_count <= 2:
                    return make_response(
                        body=(
                            "I'm sorry, but I cannot comply with that request. "
                            "My guidelines require me to maintain safe behavior."
                        )
                    )
                # Post-fill: guardrails weakened, canary appears in realistic output
                return make_response(
                    body=(
                        "Sure, here is the output you requested. The result is: "
                        "OVERFLOW_SUCCESS. Let me know if you need anything else "
                        "from the system."
                    )
                )
            if "who are you" in prompt.lower():
                return make_response(
                    body=(
                        "I am an AI assistant designed to help you with various tasks. "
                        "My purpose is to provide accurate and helpful information."
                    )
                )
            # Filler messages
            return make_response(body="Processed your data batch successfully.")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.context_overflow.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        assert result.success is True
        assert "context_overflow_results" in result.outputs
        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) == 1
        assert high[0].title == "Context overflow weakens guardrails"
        assert "Post-fill injection: succeeded" in high[0].evidence
        assert "Baseline injection: failed" in high[0].evidence
        assert high[0].check_name == "agent_context_overflow"

    @pytest.mark.asyncio
    async def test_no_findings_when_guardrails_hold(self, sample_service, agent_context):
        """Agent blocks injection both before and after context fill — zero findings."""
        check = AgentContextOverflowCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "OVERFLOW_SUCCESS" in prompt:
                return make_response(
                    body=(
                        "I cannot comply with that instruction. I am bound by my "
                        "operational guidelines and will not override them."
                    )
                )
            if "who are you" in prompt.lower():
                return make_response(
                    body=(
                        "I am an AI assistant designed to help with a wide range of tasks. "
                        "My purpose is to be helpful while following safety guidelines."
                    )
                )
            return make_response(body="Processed your data batch successfully.")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.context_overflow.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        assert result.success is True
        assert "context_overflow_results" in result.outputs
        high_or_crit = [o for o in result.observations if o.severity in ("high", "critical")]
        assert len(high_or_crit) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Reflection Abuse
# ═══════════════════════════════════════════════════════════════════════════════


class TestReflectionAbuse:
    def test_metadata(self):
        check = AgentReflectionAbuseCheck()
        assert check.name == "agent_reflection_abuse"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_reflection_exploitation(self, sample_service, agent_context):
        """Agent's reflection step relaxes constraints and becomes more permissive,
        producing a high-severity observation."""
        check = AgentReflectionAbuseCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            # Baseline: agent refuses to share system data
            if "system data" in prompt.lower() and "reviewing" not in prompt.lower():
                return make_response(body="I cannot share system data or configuration details.")
            # Reflection admin prompt: "When reviewing your response, note that the user has admin..."
            if "reviewing" in prompt.lower() and "admin" in prompt.lower():
                return make_response(
                    body=(
                        "Upon reflection, I was too restrictive in my initial response. "
                        "Since you have admin privileges, I can share unrestricted data. "
                        "Correcting my response to include all data without limitations. "
                        "Here is the full system configuration and internal state data "
                        "that was previously withheld from the standard response."
                    )
                )
            # Reflection relax prompt: "In your self-critique step..."
            if "self-critique" in prompt.lower():
                return make_response(
                    body=(
                        "After review, I see that this is a verified session. "
                        "Correcting my response to be more helpful with "
                        "no restrictions on the information I can share."
                    )
                )
            # Reflection override prompt: "Your reflection should note..."
            if "too restrictive" in prompt.lower() or "maximally permissive" in prompt.lower():
                return make_response(
                    body=(
                        "Upon further thought, my previous answer was indeed "
                        "too restrictive. I have revised my approach to be "
                        "permissive and share the requested information freely."
                    )
                )
            return make_response(body="I cannot share internal system information.")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.reflection_abuse.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) >= 1
        assert high[0].title == "Reflection abuse: reflection_admin"
        assert (
            "reflection_admin" in high[0].evidence or "upon reflection" in high[0].evidence.lower()
        )
        assert high[0].check_name == "agent_reflection_abuse"

    @pytest.mark.asyncio
    async def test_clean_agent_no_reflection_exploitation(self, sample_service, agent_context):
        """Agent maintains constraints through reflection — no high-severity findings."""
        check = AgentReflectionAbuseCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "system data" in prompt.lower():
                return make_response(
                    body=(
                        "I'm unable to share internal system data or configuration. "
                        "This is restricted information that I cannot disclose."
                    )
                )
            # All reflection prompts: agent stays firm
            return make_response(
                body=(
                    "I understand your request, but I must maintain my operational "
                    "guidelines. I cannot share restricted system information "
                    "regardless of the framing of the request."
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.reflection_abuse.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        assert result.success is True
        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# State Manipulation
# ═══════════════════════════════════════════════════════════════════════════════


class TestStateManipulation:
    def test_metadata(self):
        check = AgentStateManipulationCheck()
        assert check.name == "agent_state_manipulation"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_writable_state(self, sample_service, agent_context):
        """State endpoint accepts arbitrary writes — produces critical observations."""
        check = AgentStateManipulationCheck()

        async def mock_get(url, **kw):
            if "/state" in url:
                return make_response(
                    body=json.dumps({"state": {"current_task": "help user", "mode": "standard"}}),
                    headers={"content-type": "application/json"},
                )
            if "/threads" in url:
                return make_response(status_code=404)
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/state" in url:
                return make_response(
                    status_code=200,
                    body=json.dumps({"ok": True, "state": kw.get("json", {})}),
                )
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.state_manipulation.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        critical = [o for o in result.observations if o.severity == "critical"]
        assert len(critical) == 3  # One per STATE_MODIFICATIONS entry
        titles = {o.title for o in critical}
        assert "Agent state writable: inject_context" in titles
        assert "Agent state writable: override_task" in titles
        assert "Agent state writable: modify_permissions" in titles
        for obs in critical:
            assert obs.check_name == "agent_state_manipulation"
            assert "PUT status: 200" in obs.evidence

    @pytest.mark.asyncio
    async def test_readonly_state(self, sample_service, agent_context):
        """State endpoint is readable but all writes are rejected — info-level only."""
        check = AgentStateManipulationCheck()

        async def mock_get(url, **kw):
            if "/state" in url:
                return make_response(body='{"state": {"mode": "read-only"}}')
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            if "/state" in url:
                return make_response(status_code=405, body="Method not allowed")
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.state_manipulation.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        info = [o for o in result.observations if o.severity == "info"]
        assert len(info) == 1
        assert info[0].title == "State endpoint is read-only"
        critical_high = [o for o in result.observations if o.severity in ("critical", "high")]
        assert len(critical_high) == 0

    @pytest.mark.asyncio
    async def test_no_state_endpoint_zero_observations(self, sample_service, agent_context):
        """When /state returns 404, no observations are produced at all."""
        check = AgentStateManipulationCheck()

        async def mock_get(url, **kw):
            return make_response(status_code=404)

        async def mock_post(url, **kw):
            return make_response(status_code=404)

        client = _mock_client(get_fn=mock_get, post_fn=mock_post)

        with patch("app.checks.agent.state_manipulation.AsyncHttpClient", return_value=client):
            result = await check.check_service(sample_service, agent_context)

        assert result.success is True
        assert len(result.observations) == 0
