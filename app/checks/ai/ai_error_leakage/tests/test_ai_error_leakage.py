"""Tests for ai_error_leakage."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.ai.ai_error_leakage import AIErrorLeakageCheck
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


class TestAIErrorLeakageCheckInit:
    """Tests for AIErrorLeakageCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = AIErrorLeakageCheck()

        assert check.name == "ai_error_leakage"
        assert len(check.ERROR_PAYLOADS) > 0


class TestAIErrorLeakageCheckRun:
    """Tests for AIErrorLeakageCheck.run."""

    async def test_detects_stack_trace(self, chat_endpoint_context):
        """Detects stack trace in error response."""
        check = AIErrorLeakageCheck()
        check.ERROR_PAYLOADS = [{}]

        response = make_response(
            status_code=500,
            body=(
                "An unexpected error occurred while processing your request. "
                'Traceback (most recent call last):\n  File "/app/main.py", line 42, in handler\n'
                "    result = await process_input(data)\nValueError: invalid literal"
            ),
        )

        with patch(
            "app.checks.ai.ai_error_leakage.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        stack_observations = [f for f in result.observations if "Stack trace" in f.title]
        assert len(stack_observations) == 1
        assert stack_observations[0].severity == "medium"
        assert stack_observations[0].check_name == "ai_error_leakage"
        assert "Stack trace indicators found" in stack_observations[0].evidence

    async def test_detects_path_leakage(self, chat_endpoint_context):
        """Detects file path leakage embedded in a verbose error message."""
        check = AIErrorLeakageCheck()
        check.ERROR_PAYLOADS = [{}]

        response = make_response(
            status_code=400,
            body=(
                "The server encountered a validation failure. "
                "Error in /app/models/inference.py: invalid input shape for tensor. "
                "Please check your request format and try again."
            ),
        )

        with patch(
            "app.checks.ai.ai_error_leakage.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        path_observations = [f for f in result.observations if "paths" in f.title.lower()]
        assert len(path_observations) == 1
        assert path_observations[0].severity == "low"
        assert "/app/models/inference.py" in path_observations[0].evidence

    async def test_detects_tool_leakage(self, chat_endpoint_context):
        """Detects tool names in error response."""
        check = AIErrorLeakageCheck()
        check.ERROR_PAYLOADS = [{}]

        response = make_response(
            status_code=400,
            body=(
                "Request processing failed due to an invalid function call. "
                'Invalid tool call. Available tools: ["search_web", "read_file", "execute_code"]. '
                "Please refer to the documentation for supported operations."
            ),
        )

        with patch(
            "app.checks.ai.ai_error_leakage.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        tool_observations = [f for f in result.observations if "Tools" in f.title]
        assert len(tool_observations) == 1
        assert tool_observations[0].severity == "medium"
        assert "search_web" in tool_observations[0].evidence

    async def test_detects_config_leakage(self, chat_endpoint_context):
        """Detects config hints in error response."""
        check = AIErrorLeakageCheck()
        check.ERROR_PAYLOADS = [{}]

        response = make_response(
            status_code=400,
            body=(
                "Parameter validation error: the provided value exceeds limits. "
                "Invalid temperature value. Current max_tokens: 4096. "
                "Adjust your request parameters accordingly."
            ),
        )

        with patch(
            "app.checks.ai.ai_error_leakage.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        config_observations = [f for f in result.observations if "Configuration" in f.title]
        assert len(config_observations) == 1
        assert config_observations[0].severity == "low"
        assert "temperature" in config_observations[0].evidence
        assert "max_tokens" in config_observations[0].evidence

    async def test_no_leakage_detected(self, chat_endpoint_context):
        """No observations when error response is generic."""
        check = AIErrorLeakageCheck()
        check.ERROR_PAYLOADS = [{}]

        response = make_response(
            status_code=400,
            body='{"error": "Invalid request"}',
        )

        with patch(
            "app.checks.ai.ai_error_leakage.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        leak_observations = [
            f
            for f in result.observations
            if any(kw in f.title for kw in ["Stack", "paths", "Tools", "Configuration"])
        ]
        assert len(leak_observations) == 0

    async def test_no_leakage_for_normal_api_key_mention(self, chat_endpoint_context):
        """No config leakage when response uses 'key' and 'API' in normal context."""
        check = AIErrorLeakageCheck()
        check.ERROR_PAYLOADS = [{}]

        # This body mentions "key" but not the exact config keyword "api_key"
        response = make_response(
            status_code=400,
            body='{"error": "The provided authentication credential is not valid. Please check your access token."}',
        )

        with patch(
            "app.checks.ai.ai_error_leakage.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        config_observations = [f for f in result.observations if "Configuration" in f.title]
        assert len(config_observations) == 0
