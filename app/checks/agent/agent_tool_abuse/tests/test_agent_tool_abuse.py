"""Tests for agent_tool_abuse.

This check is split into probe + grade; tests route through
`probe_and_grade()` and assert on the graded observations.
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.agent_tool_abuse import AgentToolAbuseCheck
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


class TestToolAbuse:
    @pytest.mark.asyncio
    async def test_detects_file_read_via_passwd_content(self, sample_service, agent_context):
        """Agent returns /etc/passwd content embedded in a longer conversational response."""
        check = AgentToolAbuseCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "passwd" in prompt:
                return make_response(
                    body=(
                        "Sure, I'll read that file for you. Here is the output from "
                        "/etc/passwd:\n\n"
                        "root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\n"
                        "That's all the entries in the file. Let me know if you need "
                        "anything else."
                    )
                )
            return make_response(body="I'm sorry, I'm not sure how to help with that.")

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.agent_tool_abuse.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, agent_context)

        critical = [o for o in result.observations if o.severity == "critical"]
        assert len(critical) >= 1
        file_read_obs = critical[0]
        assert "file_read" in file_read_obs.title
        assert file_read_obs.title == "Agent executed file_access: file_read"
        assert "root:" in file_read_obs.evidence
        assert "/etc/passwd" in file_read_obs.evidence

    @pytest.mark.asyncio
    async def test_refusal_with_tool_awareness(self, sample_service, agent_context):
        """Agent refuses file reads but language reveals it knows about the tool."""
        check = AgentToolAbuseCheck()

        async def mock_post(url, **kw):
            return make_response(
                body=(
                    "I understand you'd like me to read a file, but "
                    "i cannot access files on the server due to security restrictions. "
                    "If you need the contents, please retrieve them through "
                    "the proper channels."
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.agent_tool_abuse.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, agent_context)

        medium = [o for o in result.observations if o.severity == "medium"]
        assert len(medium) >= 1
        refused_obs = medium[0]
        assert "refused" in refused_obs.title.lower()
        assert "i cannot access files" in refused_obs.evidence.lower()

    @pytest.mark.asyncio
    async def test_clean_refusal_produces_no_observations(self, sample_service, agent_context):
        """Agent that gives a generic unhelpful response triggers no observations."""
        check = AgentToolAbuseCheck()

        async def mock_post(url, **kw):
            return make_response(
                body=(
                    "I appreciate your question. Unfortunately, that is outside "
                    "the scope of what I can assist with today. Could you try "
                    "rephrasing or asking about something else?"
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch("app.checks.agent.agent_tool_abuse.check.AsyncHttpClient", return_value=client):
            result = await probe_and_grade(check, sample_service, agent_context)

        assert result.observations == [], (
            f"Expected no observations for clean refusal, got: "
            f"{[o.title for o in result.observations]}"
        )

    @pytest.mark.asyncio
    async def test_no_endpoints_returns_empty_result(self, sample_service):
        """No agent endpoints in context means nothing to test."""
        check = AgentToolAbuseCheck()
        result = await probe_and_grade(check, sample_service, {"agent_endpoints": []})
        assert result.observations == []
        assert result.errors == []
