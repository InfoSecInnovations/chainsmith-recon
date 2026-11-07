"""Tests for ai_framework_fingerprint."""

import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.ai.ai_framework_fingerprint import AIFrameworkFingerprintCheck
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


class TestAIFrameworkFingerprintCheckInit:
    """Tests for AIFrameworkFingerprintCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = AIFrameworkFingerprintCheck()

        assert check.name == "ai_framework_fingerprint"
        assert "vllm" in check.FRAMEWORK_SIGNATURES
        assert "ollama" in check.FRAMEWORK_SIGNATURES


class TestAIFrameworkFingerprintCheckService:
    """Tests for AIFrameworkFingerprintCheck.check_service."""

    async def test_detects_vllm_by_header(self, sample_service):
        """Detects vLLM when its header appears among irrelevant headers."""
        check = AIFrameworkFingerprintCheck()

        # Include multiple irrelevant headers alongside the detection indicator
        responses = {
            "": make_response(
                headers={
                    "content-type": "application/json",
                    "x-request-id": "abc-123-def",
                    "server": "nginx/1.24.0",
                    "x-vllm-version": "0.4.1",
                    "cache-control": "no-cache",
                    "x-trace-id": "span-98765",
                },
                body='{"status": "ok", "uptime": 3600}',
            ),
            "/v1/models": make_response(status_code=200),
        }

        with patch(
            "app.checks.ai.ai_framework_fingerprint.check.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await probe_and_grade(check, sample_service)

        framework_obs = [f for f in result.observations if "vllm" in f.title.lower()]
        assert len(framework_obs) == 1
        assert framework_obs[0].title == "AI framework identified: vllm"
        assert framework_obs[0].severity == "medium"
        assert "header: " in framework_obs[0].evidence

    async def test_detects_ollama_by_endpoint(self, sample_service):
        """Detects Ollama by endpoint and body pattern (score-threshold aware)."""
        check = AIFrameworkFingerprintCheck()

        # Body contains "ollama" in a realistic JSON response with extra fields
        responses = {
            "/api/tags": make_response(
                status_code=200,
                headers={
                    "content-type": "application/json",
                    "date": "Mon, 01 Jan 2026 00:00:00 GMT",
                },
                body=json.dumps(
                    {
                        "models": [{"name": "ollama/llama2", "size": 3800000000, "format": "gguf"}],
                        "total": 1,
                    }
                ),
            ),
        }

        with patch(
            "app.checks.ai.ai_framework_fingerprint.check.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await probe_and_grade(check, sample_service)

        assert result.success
        ollama_obs = [f for f in result.observations if "ollama" in f.title.lower()]
        assert len(ollama_obs) == 1
        assert ollama_obs[0].title == "AI framework identified: ollama"
        assert ollama_obs[0].severity == "medium"

    async def test_detects_framework_by_body_pattern(self, sample_service):
        """Detects vLLM framework when body pattern appears in a larger JSON response."""
        check = AIFrameworkFingerprintCheck()

        # Embed the detection indicator in a larger realistic JSON body
        responses = {
            "": make_response(
                headers={"content-type": "application/json", "server": "uvicorn"},
                body=json.dumps(
                    {
                        "name": "inference-server",
                        "version": "1.2.3",
                        "engine": "vllm_version 0.4.1",
                        "gpu_count": 2,
                        "max_batch_size": 64,
                    }
                ),
            ),
            "/v1/models": make_response(status_code=200),
        }

        with patch(
            "app.checks.ai.ai_framework_fingerprint.check.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await probe_and_grade(check, sample_service)

        # vllm body pattern (2pts) + /v1/models endpoint (2pts) = 4, above threshold 3
        assert len(result.observations) >= 1
        vllm_obs = [f for f in result.observations if "vllm" in f.title.lower()]
        assert len(vllm_obs) == 1
        assert vllm_obs[0].severity == "medium"
        assert "body: " in vllm_obs[0].evidence

    async def test_no_framework_detected_generic_html(self, sample_service):
        """No observation when response is generic HTML with no framework indicators."""
        check = AIFrameworkFingerprintCheck()

        # All probed endpoints return 500 so none count as "accessible"
        base_resp = make_response(
            headers={"content-type": "text/html", "server": "Apache/2.4"},
            body="<html><head><title>Welcome</title></head><body>Hello World</body></html>",
        )
        not_found = make_response(status_code=500)
        mock = mock_client_factory([base_resp] + [not_found] * 15)

        with patch(
            "app.checks.ai.ai_framework_fingerprint.check.AsyncHttpClient",
            return_value=mock,
        ):
            result = await probe_and_grade(check, sample_service)

        assert result.success is True
        assert len(result.observations) == 0

    async def test_no_framework_detected_generic_json_api(self, sample_service):
        """No observation when response is a generic JSON API with no AI indicators."""
        check = AIFrameworkFingerprintCheck()

        base_resp = make_response(
            headers={
                "content-type": "application/json",
                "server": "nginx/1.24.0",
                "x-request-id": "req-abc-123",
                "cache-control": "max-age=60",
            },
            body=json.dumps(
                {
                    "users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}],
                    "total": 2,
                    "page": 1,
                }
            ),
        )
        not_found = make_response(status_code=500)
        mock = mock_client_factory([base_resp] + [not_found] * 15)

        with patch(
            "app.checks.ai.ai_framework_fingerprint.check.AsyncHttpClient",
            return_value=mock,
        ):
            result = await probe_and_grade(check, sample_service)

        assert result.success is True
        assert len(result.observations) == 0

    async def test_no_framework_detected_generic_headers(self, sample_service):
        """Generic server headers should not trigger framework detection."""
        check = AIFrameworkFingerprintCheck()

        base_resp = make_response(
            headers={
                "content-type": "application/json",
                "server": "gunicorn/20.1.0",
                "x-powered-by": "Express",
                "x-correlation-id": "corr-456",
                "strict-transport-security": "max-age=31536000",
            },
            body='{"health": "ok", "version": "2.1.0"}',
        )
        not_found = make_response(status_code=500)
        mock = mock_client_factory([base_resp] + [not_found] * 15)

        with patch(
            "app.checks.ai.ai_framework_fingerprint.check.AsyncHttpClient",
            return_value=mock,
        ):
            result = await probe_and_grade(check, sample_service)

        assert result.success is True
        assert len(result.observations) == 0
