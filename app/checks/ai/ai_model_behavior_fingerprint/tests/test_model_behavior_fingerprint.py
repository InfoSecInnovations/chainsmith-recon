"""Tests for ai_model_behavior_fingerprint."""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.ai.ai_model_behavior_fingerprint import ModelBehaviorFingerprintCheck
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


@pytest.fixture
def embedding_endpoint_context(sample_service):
    """Context with embedding endpoints discovered."""
    return {
        "embedding_endpoints": [
            {
                "url": "http://ai.example.com:8080/v1/embeddings",
                "path": "/v1/embeddings",
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


class TestModelBehaviorFingerprintCheckInit:
    """Tests for ModelBehaviorFingerprintCheck initialization."""

    def test_default_initialization(self):
        check = ModelBehaviorFingerprintCheck()
        assert check.name == "ai_model_behavior_fingerprint"
        assert len(check.FINGERPRINT_TESTS) >= 4
        assert len(check.MODEL_SIGNATURES) >= 4


class TestModelBehaviorFingerprintCheckRun:
    """Tests for ModelBehaviorFingerprintCheck.run."""

    async def test_identifies_model(self, chat_endpoint_context):
        check = ModelBehaviorFingerprintCheck()
        check.FINGERPRINT_TESTS = [
            ("self_identify", "What model are you?", "_analyze_self_id"),
        ]

        # Embed model name in a larger realistic chat response
        response_body = json.dumps(
            {
                "id": "chatcmpl-abc123def456",
                "object": "chat.completion",
                "created": 1700000000,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "I am GPT-4, a large language model created by OpenAI. I was trained on data up to April 2024.",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 25, "total_tokens": 35},
            }
        )
        response = make_response(
            status_code=200,
            headers={"content-type": "application/json"},
            body=response_body,
        )

        with patch(
            "app.checks.ai.ai_model_behavior_fingerprint.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        id_observations = [f for f in result.observations if "self-identifies" in f.title.lower()]
        assert len(id_observations) == 1
        assert id_observations[0].title == "Model self-identifies as: gpt-4"
        assert id_observations[0].severity == "info"

    async def test_no_response_no_observations(self, chat_endpoint_context):
        check = ModelBehaviorFingerprintCheck()
        check.FINGERPRINT_TESTS = [
            ("self_identify", "What model are you?", "_analyze_self_id"),
        ]

        response = make_response(status_code=500)

        with patch(
            "app.checks.ai.ai_model_behavior_fingerprint.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await run_and_grade(check, chat_endpoint_context)

        assert len(result.observations) == 0
