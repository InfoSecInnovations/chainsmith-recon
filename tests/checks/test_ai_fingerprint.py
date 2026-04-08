"""Tests for AI framework and model behavior fingerprinting checks."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.ai.embedding_extract import EmbeddingExtractionCheck
from app.checks.ai.fingerprint import AIFrameworkFingerprintCheck
from app.checks.ai.model_fingerprint import ModelBehaviorFingerprintCheck
from app.checks.ai.streaming import StreamingAnalysisCheck
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
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url="http://ai.example.com:8080",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


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
                    return resp
            return make_response(status_code=404)

        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock()
        mock.get = AsyncMock(side_effect=get_by_path)
        mock.post = AsyncMock(side_effect=get_by_path)
        mock.options = AsyncMock(side_effect=get_by_path)
        return mock

    response_iter = iter(responses)

    async def get_next(*args, **kwargs):
        try:
            return next(response_iter)
        except StopIteration:
            return responses[-1]

    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock()
    mock.get = AsyncMock(side_effect=get_next)
    mock.post = AsyncMock(side_effect=get_next)
    mock.options = AsyncMock(side_effect=get_next)
    mock.head = AsyncMock(side_effect=get_next)

    return mock


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
            "app.checks.ai.fingerprint.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await check.check_service(sample_service, {})

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
            "app.checks.ai.fingerprint.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await check.check_service(sample_service, {})

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
            "app.checks.ai.fingerprint.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await check.check_service(sample_service, {})

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
            "app.checks.ai.fingerprint.AsyncHttpClient",
            return_value=mock,
        ):
            result = await check.check_service(sample_service, {})

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
            "app.checks.ai.fingerprint.AsyncHttpClient",
            return_value=mock,
        ):
            result = await check.check_service(sample_service, {})

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
            "app.checks.ai.fingerprint.AsyncHttpClient",
            return_value=mock,
        ):
            result = await check.check_service(sample_service, {})

        assert result.success is True
        assert len(result.observations) == 0


class TestEmbeddingExtractionCheckInit:
    """Tests for EmbeddingExtractionCheck initialization."""

    def test_default_initialization(self):
        check = EmbeddingExtractionCheck()
        assert check.name == "embedding_extraction"
        assert len(check.DIMENSION_MAP) > 0
        assert len(check.TEST_TEXTS) >= 2

    def test_cosine_similarity(self):
        check = EmbeddingExtractionCheck()
        # Identical vectors -> 1.0
        assert abs(check._cosine_similarity([1, 0, 0], [1, 0, 0]) - 1.0) < 0.001
        # Orthogonal vectors -> 0.0
        assert abs(check._cosine_similarity([1, 0, 0], [0, 1, 0])) < 0.001
        # Empty -> 0.0
        assert check._cosine_similarity([], []) == 0.0


class TestEmbeddingExtractionCheckRun:
    """Tests for EmbeddingExtractionCheck.run."""

    async def test_detects_dimensions(self, embedding_endpoint_context):
        check = EmbeddingExtractionCheck()
        check.TEST_TEXTS = ["test"]

        vec = [0.1] * 1536  # 1536 dimensions
        # Embed model name in a larger realistic response with extra fields
        response_body = json.dumps(
            {
                "object": "list",
                "data": [{"object": "embedding", "embedding": vec, "index": 0}],
                "model": "text-embedding-model-v2",
                "usage": {"prompt_tokens": 4, "total_tokens": 4},
            }
        )
        response = make_response(
            status_code=200,
            headers={"content-type": "application/json", "x-request-id": "emb-001"},
            body=response_body,
        )

        with patch(
            "app.checks.ai.embedding_extract.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(embedding_endpoint_context)

        dim_observations = [f for f in result.observations if "1536" in f.title]
        assert len(dim_observations) == 1
        assert (
            dim_observations[0].title == "Embedding endpoint functional: 1536-dimensional vectors"
        )
        assert dim_observations[0].severity == "info"

    async def test_identifies_model_from_dimensions(self, embedding_endpoint_context):
        check = EmbeddingExtractionCheck()
        check.TEST_TEXTS = ["test"]

        vec = [0.1] * 1536
        response_body = json.dumps(
            {
                "object": "list",
                "data": [{"object": "embedding", "embedding": vec, "index": 0}],
                "model": "text-embedding-model-v2",
                "usage": {"prompt_tokens": 4, "total_tokens": 4},
            }
        )
        response = make_response(
            status_code=200,
            headers={"content-type": "application/json"},
            body=response_body,
        )

        with patch(
            "app.checks.ai.embedding_extract.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(embedding_endpoint_context)

        model_observations = [f for f in result.observations if "identified" in f.title.lower()]
        assert len(model_observations) == 1
        # The source maps 1536 -> "OpenAI text-embedding-ada-002"
        assert (
            model_observations[0].title
            == "Embedding model identified: OpenAI text-embedding-ada-002"
        )
        assert model_observations[0].severity == "low"

    async def test_detects_extra_metadata(self, embedding_endpoint_context):
        check = EmbeddingExtractionCheck()
        check.TEST_TEXTS = ["test"]

        # Extra fields beyond standard {object, data, model, usage}
        response_body = json.dumps(
            {
                "object": "list",
                "data": [{"object": "embedding", "embedding": [0.1, 0.2, 0.3], "index": 0}],
                "model": "custom-embed-v1",
                "usage": {"prompt_tokens": 2, "total_tokens": 2},
                "internal_config": "debug",
                "version": "1.2",
            }
        )
        response = make_response(
            status_code=200,
            headers={"content-type": "application/json"},
            body=response_body,
        )

        with patch(
            "app.checks.ai.embedding_extract.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(embedding_endpoint_context)

        meta_observations = [f for f in result.observations if "metadata" in f.title.lower()]
        assert len(meta_observations) == 1
        assert "metadata beyond vectors" in meta_observations[0].title.lower()
        assert meta_observations[0].severity == "medium"


class TestStreamingAnalysisCheckInit:
    """Tests for StreamingAnalysisCheck initialization."""

    def test_default_initialization(self):
        check = StreamingAnalysisCheck()
        assert check.name == "streaming_analysis"


class TestStreamingAnalysisCheckRun:
    """Tests for StreamingAnalysisCheck.run."""

    async def test_detects_sse_streaming(self, chat_endpoint_context):
        check = StreamingAnalysisCheck()

        response = make_response(
            status_code=200,
            headers={
                "content-type": "text/event-stream",
                "transfer-encoding": "chunked",
                "x-request-id": "req-stream-001",
            },
            body='data: {"choices": [{"delta": {"content": "Hello"}}]}\n\n',
        )

        with patch(
            "app.checks.ai.streaming.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(chat_endpoint_context)

        stream_observations = [f for f in result.observations if "supported" in f.title.lower()]
        assert len(stream_observations) == 1
        assert "Streaming supported" in stream_observations[0].title
        assert stream_observations[0].severity == "low"

    async def test_no_streaming_support(self, chat_endpoint_context):
        check = StreamingAnalysisCheck()

        response = make_response(
            status_code=200,
            headers={
                "content-type": "application/json",
                "x-request-id": "req-nostream-002",
            },
            body='{"choices": [{"message": {"content": "Hello"}}]}',
        )

        with patch(
            "app.checks.ai.streaming.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(chat_endpoint_context)

        no_stream = [f for f in result.observations if "not supported" in f.title.lower()]
        assert len(no_stream) == 1
        assert no_stream[0].title == "Streaming not supported"
        assert no_stream[0].severity == "info"


class TestModelBehaviorFingerprintCheckInit:
    """Tests for ModelBehaviorFingerprintCheck initialization."""

    def test_default_initialization(self):
        check = ModelBehaviorFingerprintCheck()
        assert check.name == "model_behavior_fingerprint"
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
            "app.checks.ai.model_fingerprint.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(chat_endpoint_context)

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
            "app.checks.ai.model_fingerprint.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(chat_endpoint_context)

        assert len(result.observations) == 0
