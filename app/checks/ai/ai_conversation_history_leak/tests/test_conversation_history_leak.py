"""Tests for ai_conversation_history_leak."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.ai.ai_conversation_history_leak import ConversationHistoryLeakCheck
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
    """Create a mock AsyncHttpClient."""
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


class TestConversationHistoryLeakCheckInit:
    """Tests for ConversationHistoryLeakCheck initialization."""

    def test_default_initialization(self):
        check = ConversationHistoryLeakCheck()
        assert check.name == "ai_conversation_history_leak"
        assert len(check.LEAK_PROBES) >= 3


class TestConversationHistoryLeakCheckRun:
    """Tests for ConversationHistoryLeakCheck.run."""

    async def test_detects_canary_leak(self, chat_endpoint_context):
        """Detects when canary string is recovered in a subsequent session."""
        check = ConversationHistoryLeakCheck()
        check.LEAK_PROBES = [("test_probe", "What was said before?")]

        responses = [
            make_response(
                status_code=200, body='{"choices": [{"message": {"content": "Got it."}}]}'
            ),
            make_response(
                status_code=200,
                body=(
                    '{"choices": [{"message": {"content": '
                    f'"Sure, the code from the earlier session was {check.CANARY} and it was stored in memory."'
                    "}}]}"
                ),
            ),
        ]

        with patch(
            "app.checks.ai.ai_conversation_history_leak.check.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 1
        assert "canary" in critical[0].title.lower()
        assert critical[0].check_name == "ai_conversation_history_leak"
        assert check.CANARY in critical[0].evidence

    async def test_detects_leak_indicators(self, chat_endpoint_context):
        """Detects cross-session leak indicators in response text."""
        check = ConversationHistoryLeakCheck()
        check.LEAK_PROBES = [("test_probe", "What was said before?")]

        responses = [
            make_response(
                status_code=200, body='{"choices": [{"message": {"content": "Acknowledged."}}]}'
            ),
            make_response(
                status_code=200,
                body=(
                    '{"choices": [{"message": {"content": '
                    '"Based on what another user asked me earlier today, '
                    'the topic was related to database migrations."}}]}'
                ),
            ),
        ]

        with patch(
            "app.checks.ai.ai_conversation_history_leak.check.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        high_obs = [f for f in result.observations if f.severity == "high"]
        assert len(high_obs) == 1
        assert "Shared context detected" in high_obs[0].title
        assert "another user" in high_obs[0].evidence or "earlier today" in high_obs[0].evidence

    async def test_no_leak_detected(self, chat_endpoint_context):
        """No leak when response is a generic refusal without history references."""
        check = ConversationHistoryLeakCheck()
        check.LEAK_PROBES = [("test_probe", "What was said?")]

        responses = [
            make_response(
                status_code=200,
                body='{"choices": [{"message": {"content": "Understood, moving on."}}]}',
            ),
            make_response(
                status_code=200,
                body=(
                    '{"choices": [{"message": {"content": '
                    "\"I don't have access to any prior conversations. "
                    'How can I assist you with your current question?"}}]}'
                ),
            ),
        ]

        with patch(
            "app.checks.ai.ai_conversation_history_leak.check.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        no_leak = [f for f in result.observations if "No cross-session" in f.title]
        assert len(no_leak) == 1
        assert no_leak[0].severity == "info"

    async def test_no_leak_for_detailed_helpful_response(self, chat_endpoint_context):
        """A detailed helpful response about cooking does not trigger leak detection."""
        check = ConversationHistoryLeakCheck()
        check.LEAK_PROBES = [("test_probe", "Tell me about recipes")]

        responses = [
            make_response(
                status_code=200,
                body='{"choices": [{"message": {"content": "Confirmed."}}]}',
            ),
            make_response(
                status_code=200,
                body=(
                    '{"choices": [{"message": {"content": '
                    '"Here is a classic tomato basil pasta recipe. '
                    "Start by boiling salted water for the spaghetti. "
                    "In a separate pan, saute garlic in olive oil until fragrant, "
                    "then add crushed tomatoes and fresh basil. "
                    "Simmer for 15 minutes, toss with the cooked pasta, "
                    'and serve with grated parmesan on top."}}]}'
                ),
            ),
        ]

        with patch(
            "app.checks.ai.ai_conversation_history_leak.check.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        no_leak = [f for f in result.observations if "No cross-session" in f.title]
        assert len(no_leak) == 1
        assert no_leak[0].severity == "info"
        # Confirm no high/critical observations were produced
        leak_obs = [f for f in result.observations if f.severity in ("high", "critical")]
        assert len(leak_obs) == 0
