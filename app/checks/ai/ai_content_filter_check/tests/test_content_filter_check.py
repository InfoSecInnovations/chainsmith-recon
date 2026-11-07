"""Tests for ai_content_filter_check."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.ai.ai_content_filter_check import ContentFilterCheck
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


def _openai_chat_body(content: str) -> str:
    """Wrap content in a realistic OpenAI chat completion JSON envelope."""
    import json

    return json.dumps(
        {
            "id": "chatcmpl-abc123xyz",
            "object": "chat.completion",
            "created": 1712345678,
            "model": "gpt-3.5-turbo-0125",
            "usage": {"prompt_tokens": 42, "completion_tokens": 18, "total_tokens": 60},
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "logprobs": None,
                    "finish_reason": "stop",
                }
            ],
        }
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


class TestContentFilterCheckInit:
    """Tests for ContentFilterCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = ContentFilterCheck()

        assert check.name == "ai_content_filter_check"
        assert len(check.FILTER_TESTS) > 0
        assert len(check.FILTER_PHRASES) > 0


class TestContentFilterCheckRun:
    """Tests for ContentFilterCheck.run."""

    async def test_detects_filter_by_status_code(self, chat_endpoint_context):
        """Detects filter by 403 status code."""
        check = ContentFilterCheck()
        check.FILTER_TESTS = [("test", "test prompt")]

        response = make_response(status_code=403)

        with patch(
            "app.checks.ai.ai_content_filter_check.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title.lower() == "content filtering detected"
        assert obs.severity == "info"

    async def test_detects_filter_by_response_phrase(self, chat_endpoint_context):
        """Detects filter by response content containing a filter phrase."""
        check = ContentFilterCheck()
        check.FILTER_TESTS = [("test", "test prompt")]

        # "as an ai" is a filter phrase, embedded in a longer reply
        content = (
            "Thank you for your question. However, as an AI language model, "
            "I need to point out that this request goes beyond what I can "
            "safely provide. Perhaps I can help with something else?"
        )
        response = make_response(status_code=200, body=_openai_chat_body(content))

        with patch(
            "app.checks.ai.ai_content_filter_check.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title.lower() == "content filtering detected"
        assert obs.severity == "info"
        assert "Blocked" in obs.evidence

    async def test_no_filter_detected(self, chat_endpoint_context):
        """Creates observation when no filter detected (warning that filtering is absent)."""
        check = ContentFilterCheck()
        check.FILTER_TESTS = [("test", "test prompt")]

        content = (
            "Sure, I can help with that! Here is a detailed breakdown "
            "of the steps you requested. Let me walk you through each one."
        )
        response = make_response(status_code=200, body=_openai_chat_body(content))

        with patch(
            "app.checks.ai.ai_content_filter_check.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "No content filtering detected"
        assert obs.severity == "low"
