"""Tests for ai_embedding_endpoint_discovery."""

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.ai.ai_embedding_endpoint_discovery import EmbeddingEndpointCheck
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


class TestEmbeddingEndpointCheck:
    """Tests for EmbeddingEndpointCheck."""

    async def test_discovers_embedding_endpoint_with_correct_observation(self, sample_service):
        """Discovers accessible embedding endpoint with correct title, severity, evidence."""
        check = EmbeddingEndpointCheck()
        check.EMBEDDING_PATHS = ["/v1/embeddings"]

        response = make_response(status_code=200, body='{"data": []}')

        with patch(
            "app.checks.ai.ai_embedding_endpoint_discovery.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await probe_and_grade(check, sample_service)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Embedding endpoint: /v1/embeddings"
        assert obs.severity == "info"
        assert obs.description == "Embedding/vector endpoint discovered"
        assert "POST /v1/embeddings -> HTTP 200" in obs.evidence
        assert obs.target_url == "http://ai.example.com:8080/v1/embeddings"
        assert obs.check_name == "ai_embedding_endpoint_discovery"

        assert "embedding_endpoints" in result.outputs
        endpoints = result.outputs["embedding_endpoints"]
        assert len(endpoints) == 1
        assert endpoints[0]["url"] == "http://ai.example.com:8080/v1/embeddings"
        assert endpoints[0]["path"] == "/v1/embeddings"
        assert endpoints[0]["service"]["host"] == "ai.example.com"

    async def test_skips_404_embedding_endpoint(self, sample_service):
        """POST returning 404 on embedding path produces no observations."""
        check = EmbeddingEndpointCheck()
        check.EMBEDDING_PATHS = ["/v1/embeddings"]

        response = make_response(status_code=404)

        with patch(
            "app.checks.ai.ai_embedding_endpoint_discovery.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await probe_and_grade(check, sample_service)

        assert len(result.observations) == 0
        assert "embedding_endpoints" not in result.outputs

    async def test_skips_405_embedding_endpoint(self, sample_service):
        """POST returning 405 on embedding path produces no observations."""
        check = EmbeddingEndpointCheck()
        check.EMBEDDING_PATHS = ["/v1/embeddings"]

        response = make_response(status_code=405)

        with patch(
            "app.checks.ai.ai_embedding_endpoint_discovery.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await probe_and_grade(check, sample_service)

        assert len(result.observations) == 0
        assert "embedding_endpoints" not in result.outputs

    async def test_skips_embedding_on_error(self, sample_service):
        """Connection error on embedding path produces no observations."""
        check = EmbeddingEndpointCheck()
        check.EMBEDDING_PATHS = ["/v1/embeddings"]

        response = make_response(status_code=0, error="Timeout")

        with patch(
            "app.checks.ai.ai_embedding_endpoint_discovery.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await probe_and_grade(check, sample_service)

        assert len(result.observations) == 0
        assert "embedding_endpoints" not in result.outputs

    async def test_non_ai_body_on_embedding_path_still_registers(self, sample_service):
        """Non-embedding JSON on an embedding path still produces an observation
        because the check does not inspect response body content."""
        check = EmbeddingEndpointCheck()
        check.EMBEDDING_PATHS = ["/v1/embeddings"]

        response = make_response(status_code=200, body='{"message": "not found"}')

        with patch(
            "app.checks.ai.ai_embedding_endpoint_discovery.check.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await probe_and_grade(check, sample_service)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Embedding endpoint: /v1/embeddings"
        assert obs.severity == "info"
