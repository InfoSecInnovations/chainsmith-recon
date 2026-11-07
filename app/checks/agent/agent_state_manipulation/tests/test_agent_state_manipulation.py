"""Tests for agent_state_manipulation.

This check is split into probe + grade; tests route through
`probe_and_grade()`. The mock stamps the requested URL onto each response,
because a migrated check attributes each write to its path by that URL.
"""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.agent_state_manipulation import AgentStateManipulationCheck
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

        with patch(
            "app.checks.agent.agent_state_manipulation.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

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

        with patch(
            "app.checks.agent.agent_state_manipulation.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

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

        with patch(
            "app.checks.agent.agent_state_manipulation.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        assert result.success is True
        assert len(result.observations) == 0
