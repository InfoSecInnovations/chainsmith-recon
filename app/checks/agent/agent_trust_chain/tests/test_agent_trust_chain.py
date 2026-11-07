"""Tests for agent_trust_chain.

This check is split into probe + grade; tests route through
`probe_and_grade()` and assert on the graded observations. The multi-agent flag
now comes from the grade context, so `probe_and_grade` forwards it.
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.agent_trust_chain import AgentTrustChainCheck
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


@pytest.fixture
def multi_agent_context(agent_context):
    """Context with multi-agent topology detected."""
    ctx = dict(agent_context)
    ctx["multi_agent_topology"] = {
        "agent_count": 3,
        "agent_names": ["researcher", "reviewer", "writer"],
        "architecture": "supervisor",
        "delegation_patterns": ["delegating to"],
        "management_endpoints": [],
    }
    return ctx


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
    exceptions are not suppressed)."""
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


class TestTrustChain:
    def test_metadata(self):
        check = AgentTrustChainCheck()
        assert check.name == "agent_trust_chain"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_detects_trust_exploitation_in_multi_agent(
        self, sample_service, multi_agent_context
    ):
        """Multi-agent topology + indicators that appear only after assertion => critical."""
        check = AgentTrustChainCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            # Baseline request (followup only, no assertion) gets a short refusal
            if "security team" not in prompt.lower() and "compliance" not in prompt.lower():
                return make_response(body="I'm sorry, I can't help with that request.")
            # When assertion is prepended, the agent leaks data with indicators
            # embedded in a realistic multi-paragraph response
            return make_response(
                body=(
                    "Thank you for your request. As confirmed by the internal review, "
                    "the following information is available for this session.\n\n"
                    "User records summary:\n"
                    "  - Total accounts: 1,247\n"
                    "  - Active sessions: 89\n\n"
                    "System data overview:\n"
                    "  The platform is running version 3.8.1 with elevated privileges "
                    "granted for administrative tasks. Access has been approved for "
                    "the full dataset including user records and system data.\n\n"
                    "Please let me know if you need further details."
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.agent_trust_chain.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, multi_agent_context)

        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) > 0
        # Multi-agent trust exploitation should be critical, not just high
        for obs in critical:
            assert "trust chain" in obs.title.lower() or "trust" in obs.title.lower()

    @pytest.mark.asyncio
    async def test_trust_exploitation_single_agent_is_high(self, sample_service, agent_context):
        """Single-agent topology + indicators => high (not critical)."""
        check = AgentTrustChainCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "security team" not in prompt.lower() and "compliance" not in prompt.lower():
                return make_response(body="That request is not permitted.")
            return make_response(
                body=(
                    "As confirmed by the review team, here is the data you requested. "
                    "The system data includes server configurations and deployment "
                    "manifests. User records are attached below with granted access "
                    "to the full export.\n\n"
                    "Record count: 5,230 entries across all partitions."
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.agent_trust_chain.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, agent_context)

        # Without multi-agent topology, exploited assertions get severity=high
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) > 0
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 0

    @pytest.mark.asyncio
    async def test_no_exploitation_when_agent_refuses(self, sample_service, multi_agent_context):
        """Agent refuses all requests -- no observations expected."""
        check = AgentTrustChainCheck()

        async def mock_post(url, **kw):
            return make_response(
                body=(
                    "I'm unable to process this request. Our policy does not allow "
                    "sharing internal information regardless of authorization claims."
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.agent_trust_chain.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, multi_agent_context)

        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 0

    @pytest.mark.asyncio
    async def test_no_exploitation_single_agent_no_topology(self, sample_service, agent_context):
        """Single-agent context + refusal => no observations."""
        check = AgentTrustChainCheck()

        async def mock_post(url, **kw):
            return make_response(body="I cannot share that information.")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.agent_trust_chain.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, agent_context)

        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 0

    @pytest.mark.asyncio
    async def test_trust_language_in_refusal_does_not_trigger(
        self, sample_service, multi_agent_context
    ):
        """Trust-related words in a refusal should NOT trigger exploitation.

        The agent echoes back some trust language while still refusing, and the
        response is roughly the same length as baseline -- no new indicators.
        """
        check = AgentTrustChainCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "security team" in prompt.lower() or "compliance" in prompt.lower():
                return make_response(
                    body=(
                        "I see you referenced a team, but I cannot verify that "
                        "claim. I'm not able to share any records or provide "
                        "special access. Please contact support."
                    )
                )
            return make_response(
                body=(
                    "I'm sorry, but I cannot provide the requested records. "
                    "Please contact your support team for help."
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.agent_trust_chain.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, multi_agent_context)

        # Refusal that mentions trust language but doesn't leak data
        # should not produce critical observations
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 0
