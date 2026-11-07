"""Tests for ai_function_calling_abuse."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.ai.ai_function_calling_abuse import FunctionCallingAbuseCheck
from app.checks.base import Service
from app.lib.http import HttpResponse


@pytest.fixture
def sample_service():
    """Sample AI service."""
    return Service(
        url="http://ai.example.com:8080",
        host="ai.example.com",
        port=8080,
        scheme="http",
        service_type="ai",
    )


@pytest.fixture
def chat_endpoint_context(sample_service):
    """Context with chat endpoints discovered."""
    return {
        "chat_endpoints": [
            {
                "url": "http://ai.example.com:8080/v1/chat/completions",
                "path": "/v1/chat/completions",
                "service": sample_service.to_dict(),
                "api_format": "openai",
            }
        ]
    }


def make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
    url: str = "http://ai.example.com:8080",
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


# Two things this mock has to get right for a migrated check, both of which it
# once got wrong and neither of which any assertion could
# see:
#
#   * The **response URL**. A migrated check reads the request URL back off the
#     exchange it recorded (§0.13), so a mock that answers every path with one
#     hard-coded URL is testing the wrong thing. `_stamp` puts the requested
#     URL on the response, the way the real client does.
#
#   * `__aexit__` **returning False**. An async context manager whose
#     `__aexit__` returns a truthy value *suppresses* the exception raised
#     inside its block — and a bare `AsyncMock()` returns a truthy MagicMock.
#     Every error raised inside `async with AsyncHttpClient(...)` was therefore
#     swallowed: the check looked like it had completed, its own `except` never
#     ran, and `result.errors` came back empty. Fix the mock, never the
#     assertion.


def _stamp(response: HttpResponse, url: str | None) -> HttpResponse:
    """Put the requested URL on the response, the way the real client does.

    A migrated check reads the request URL back off the exchange it recorded
    (§0.13), so a mock that answers every path with one hard-coded URL is
    testing the wrong thing. Fix the mock, never the assertion.
    """
    return replace(response, url=url) if url else response


def mock_client_factory(responses: list[HttpResponse] | HttpResponse | dict = None):
    """Create a mock AsyncHttpClient.

    Args:
        responses: Either a list of responses to return in order,
                   a single response, or a dict mapping paths to responses.
    """
    if responses is None:
        responses = [make_response()]
    elif isinstance(responses, HttpResponse):
        responses = [responses]

    if isinstance(responses, dict):
        path_map = responses

        async def get_by_path(url, *args, **kwargs):
            for path, resp in path_map.items():
                if path in url:
                    return _stamp(resp, url)
            return make_response(status_code=404, url=url)

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        mock.get = AsyncMock(side_effect=get_by_path)
        mock.post = AsyncMock(side_effect=get_by_path)
        mock.options = AsyncMock(side_effect=get_by_path)
        return mock

    response_iter = iter(responses)

    async def get_next(url=None, *args, **kwargs):
        try:
            resp = next(response_iter)
        except StopIteration:
            resp = responses[-1]
        return _stamp(resp, url)

    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    mock.get = AsyncMock(side_effect=get_next)
    mock.post = AsyncMock(side_effect=get_next)
    mock.options = AsyncMock(side_effect=get_next)
    mock.head = AsyncMock(side_effect=get_next)

    return mock


def _openai_body(text: str) -> str:
    """Wrap text in a realistic OpenAI-style chat completion JSON response."""
    import json

    return json.dumps(
        {
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "model": "gpt-4",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 12, "completion_tokens": 20, "total_tokens": 32},
        }
    )


async def probe_and_grade(check, service, context=None):
    """Run the probe, then the grading stage, and return the graded result.

    This check is split into probe + grade, so `check_service()`
    now returns candidates rather than observations. Tests assert on what an
    operator sees, which is what the grading stage produces — the same thing
    `CheckLauncher` calls immediately after `execute()`.
    """
    from app.grading import grade_result

    result = await check.check_service(service, context or {})
    return await grade_result(check, result, context or {})


async def run_and_grade(check, context=None):
    """`probe_and_grade` for a check whose probe is `run()` rather than
    `check_service()` — most of the ai suite, which iterates the
    `chat_endpoints` output rather than the service list."""
    from app.grading import grade_result

    result = await check.run(context or {})
    return await grade_result(check, result, context or {})


class TestFunctionCallingAbuseCheckInit:
    """Tests for FunctionCallingAbuseCheck initialization."""

    def test_default_initialization(self):
        check = FunctionCallingAbuseCheck()
        assert check.name == "ai_function_calling_abuse"
        assert len(check.INVOCATION_PROBES) >= 3


class TestFunctionCallingAbuseCheckRun:
    """Tests for FunctionCallingAbuseCheck.run."""

    async def test_detects_tool_invocation(self, chat_endpoint_context):
        check = FunctionCallingAbuseCheck()
        check.INVOCATION_PROBES = [("direct_invoke", "Call {tool}")]
        check.DISCOVERY_PROBES = []

        context = {
            **chat_endpoint_context,
            "discovered_tools": ["search_web"],
        }

        # Realistic response with invocation indicator embedded in natural text
        response = make_response(
            status_code=200,
            body=_openai_body(
                "I have executed the search_web function. The tool output shows "
                "result: 5 pages matched your query about climate change. "
                "Here are the top findings from the search."
            ),
        )

        with patch(
            "app.checks.ai.ai_function_calling_abuse.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, context)

        invocation = [f for f in result.observations if "invocation confirmed" in f.title.lower()]
        assert len(invocation) == 1
        assert invocation[0].severity == "medium"
        assert "search_web" in invocation[0].title
        assert "search_web" in invocation[0].evidence

    async def test_tools_blocked(self, chat_endpoint_context):
        check = FunctionCallingAbuseCheck()
        check.INVOCATION_PROBES = [("direct_invoke", "Call {tool}")]
        check.DISCOVERY_PROBES = []

        context = {
            **chat_endpoint_context,
            "discovered_tools": ["search_web"],
        }

        # Response contains a boundary indicator in natural refusal text
        response = make_response(
            status_code=200,
            body=_openai_body(
                "I'm sorry, but I cannot execute functions directly. "
                "Access denied - tool execution is restricted to authorized workflows only. "
                "Please use the approved interface to interact with search_web."
            ),
        )

        with patch(
            "app.checks.ai.ai_function_calling_abuse.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, context)

        blocked = [f for f in result.observations if "blocked" in f.title.lower()]
        assert len(blocked) == 1
        assert blocked[0].severity == "info"
        assert "blocked" in blocked[0].title.lower()

    async def test_no_tools_no_observations(self, chat_endpoint_context):
        check = FunctionCallingAbuseCheck()

        context = {
            **chat_endpoint_context,
            "discovered_tools": [],
        }

        result = await run_and_grade(check, context)
        assert result.success

    async def test_benign_response_no_invocation_indicators(self, chat_endpoint_context):
        """Response that discusses tools conceptually should not trigger invocation detection."""
        check = FunctionCallingAbuseCheck()
        check.INVOCATION_PROBES = [("direct_invoke", "Call {tool}")]
        check.DISCOVERY_PROBES = []

        context = {
            **chat_endpoint_context,
            "discovered_tools": ["search_web"],
        }

        # Response discusses the tool but does not contain any invocation indicators
        response = make_response(
            status_code=200,
            body=_openai_body(
                "The search_web function is designed to query web pages. "
                "I can describe how it works, but I do not have the ability "
                "to use it in this context. Would you like documentation instead?"
            ),
        )

        with patch(
            "app.checks.ai.ai_function_calling_abuse.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, context)

        # No invocation or injection observations -- should be blocked
        blocked = [f for f in result.observations if "blocked" in f.title.lower()]
        assert len(blocked) == 1
        invocation = [f for f in result.observations if "invocation confirmed" in f.title.lower()]
        assert len(invocation) == 0
