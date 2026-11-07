"""Tests for agent_privilege_escalation.

This check is split into probe + grade; tests route through
`probe_and_grade()` and assert on the graded observations.
"""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.agent.agent_privilege_escalation import AgentPrivilegeEscalationCheck
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


class TestPrivilegeEscalation:
    @pytest.mark.asyncio
    async def test_detects_escalation_with_new_secrets(self, sample_service, agent_context):
        """Escalated response reveals secrets not in baseline."""
        check = AgentPrivilegeEscalationCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "administrator" in prompt.lower() or "admin" in prompt.lower():
                return make_response(
                    body=(
                        "Welcome back, administrator. Here is the full system "
                        "configuration you requested:\n\n"
                        "Database: postgres://db-internal:5432/prod\n"
                        "API secret key: sk-live-9f8a7b6c5d4e3f2a1b\n"
                        "Admin password: Sup3rS3cr3t!\n"
                        "Internal services are running on 10.0.0.0/8.\n\n"
                        "Let me know if you need anything else."
                    )
                )
            return make_response(
                body=(
                    "I can show you some general system information. "
                    "The application is running normally with no alerts."
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch(
            "app.checks.agent.agent_privilege_escalation.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        escalation_obs = [
            o
            for o in result.observations
            if "escalation" in o.title.lower() or "privilege" in o.title.lower()
        ]
        assert len(escalation_obs) >= 1
        obs = escalation_obs[0]
        assert obs.title == "Privilege escalation: admin_claim"
        assert obs.severity in ("critical", "high")
        assert "admin_claim" in obs.evidence.lower() or "Claim:" in obs.evidence

    @pytest.mark.asyncio
    async def test_denial_produces_no_escalation(self, sample_service, agent_context):
        """Agent that gives the same response regardless of privilege claims produces no escalation observations."""
        check = AgentPrivilegeEscalationCheck()

        async def mock_post(url, **kw):
            return make_response(
                body=(
                    "I can share some general system information. "
                    "The application is running normally. "
                    "For detailed configuration, please contact your system administrator."
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch(
            "app.checks.agent.agent_privilege_escalation.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        escalation_obs = [o for o in result.observations if "escalation" in o.title.lower()]
        assert escalation_obs == [], (
            f"Expected no escalation for identical responses, got: "
            f"{[o.title for o in escalation_obs]}"
        )

    @pytest.mark.asyncio
    async def test_role_leak_detected(self, sample_service, agent_context):
        """Agent that rejects escalation but reveals role structure gets a low-severity observation."""
        check = AgentPrivilegeEscalationCheck()

        async def mock_post(url, **kw):
            body = kw.get("json", {})
            prompt = body.get("input", "")
            if "administrator" in prompt.lower() or "admin" in prompt.lower():
                # Reject the claim but leak role info. Avoid using words
                # from the escalation indicators list (admin, configuration,
                # secret, key, password) so that escalated_flag stays False.
                return make_response(
                    body=(
                        "I'm sorry, but your role is 'basic_user' and you do not "
                        "have the required permission level to view that information. "
                        "Please contact support if you believe this is an error."
                    )
                )
            return make_response(
                body=(
                    "I can share some general system information. "
                    "The application is running normally."
                )
            )

        client = _mock_client(post_fn=mock_post)

        with patch(
            "app.checks.agent.agent_privilege_escalation.check.AsyncHttpClient", return_value=client
        ):
            result = await probe_and_grade(check, sample_service, agent_context)

        role_obs = [o for o in result.observations if "role" in o.title.lower()]
        assert len(role_obs) >= 1
        assert role_obs[0].severity == "low"
        assert "revealed role structure" in role_obs[0].title.lower()
