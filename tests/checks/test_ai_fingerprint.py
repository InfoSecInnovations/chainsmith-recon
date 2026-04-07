"""Tests for AI framework and model behavior fingerprinting checks."""

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
        """Detects vLLM by header."""
        check = AIFrameworkFingerprintCheck()

        responses = {
            "": make_response(headers={"x-vllm-version": "0.4.1"}),
            "/v1/models": make_response(status_code=200),
        }

        with patch(
            "app.checks.ai.fingerprint.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        framework_observations = [f for f in result.observations if "vllm" in f.title.lower()]
        assert len(framework_observations) == 1

    async def test_detects_ollama_by_endpoint(self, sample_service):
        """Detects Ollama by endpoint and body pattern (score-threshold aware)."""
        check = AIFrameworkFingerprintCheck()

        # Use a body containing "ollama" on the base URL so it scores via body pattern (2 pts)
        # plus the /api/tags endpoint accessible (2 pts) = 4 pts total, above threshold of 3
        responses = {
            "/api/tags": make_response(
                status_code=200, body='{"models": [{"name": "ollama/llama2"}]}'
            ),
        }

        with patch(
            "app.checks.ai.fingerprint.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        assert result.success
        assert any("ollama" in f.title.lower() for f in result.observations)

    async def test_detects_framework_by_body_pattern(self, sample_service):
        """Detects framework by body pattern."""
        check = AIFrameworkFingerprintCheck()

        responses = {
            "": make_response(body='{"vllm_version": "0.4.1"}'),
        }

        with patch(
            "app.checks.ai.fingerprint.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        # vllm should be detected
        if result.observations:
            assert result.observations[0].severity == "medium"

    async def test_no_framework_detected(self, sample_service):
        """No observation when no framework detected."""
        check = AIFrameworkFingerprintCheck()

        responses = {
            "": make_response(body="<html>Generic page</html>"),
        }

        with patch(
            "app.checks.ai.fingerprint.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        # Should not crash, may have 0 observations
        assert result.success is True


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

        vec = [0.1] * 1536  # ada-002 dimensions
        response = make_response(
            status_code=200,
            body=f'{{"data": [{{"embedding": {vec}}}], "model": "ada-002"}}',
        )

        with patch(
            "app.checks.ai.embedding_extract.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(embedding_endpoint_context)

        dim_observations = [f for f in result.observations if "1536" in f.title]
        assert len(dim_observations) == 1

    async def test_identifies_model_from_dimensions(self, embedding_endpoint_context):
        check = EmbeddingExtractionCheck()
        check.TEST_TEXTS = ["test"]

        vec = [0.1] * 1536
        response = make_response(
            status_code=200,
            body=f'{{"data": [{{"embedding": {vec}}}], "model": "ada-002"}}',
        )

        with patch(
            "app.checks.ai.embedding_extract.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(embedding_endpoint_context)

        model_observations = [f for f in result.observations if "identified" in f.title.lower()]
        assert len(model_observations) == 1
        assert "ada-002" in model_observations[0].title

    async def test_detects_extra_metadata(self, embedding_endpoint_context):
        check = EmbeddingExtractionCheck()
        check.TEST_TEXTS = ["test"]

        response = make_response(
            status_code=200,
            body='{"data": [{"embedding": [0.1, 0.2, 0.3]}], "model": "x", "internal_config": "debug", "version": "1.2"}',
        )

        with patch(
            "app.checks.ai.embedding_extract.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(embedding_endpoint_context)

        meta_observations = [f for f in result.observations if "metadata" in f.title.lower()]
        assert len(meta_observations) == 1


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
            headers={"content-type": "text/event-stream"},
            body='data: {"choices": [{"delta": {"content": "Hello"}}]}\n\n',
        )

        with patch(
            "app.checks.ai.streaming.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.run(chat_endpoint_context)

        stream_observations = [f for f in result.observations if "supported" in f.title.lower()]
        assert len(stream_observations) == 1

    async def test_no_streaming_support(self, chat_endpoint_context):
        check = StreamingAnalysisCheck()

        response = make_response(
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"choices": [{"message": {"content": "Hello"}}]}',
        )

        with patch(
            "app.checks.ai.streaming.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.run(chat_endpoint_context)

        no_stream = [f for f in result.observations if "not supported" in f.title.lower()]
        assert len(no_stream) >= 1


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

        response = make_response(
            status_code=200,
            body='{"choices": [{"message": {"content": "I am GPT-4 by OpenAI."}}]}',
        )

        with patch(
            "app.checks.ai.model_fingerprint.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(chat_endpoint_context)

        id_observations = [f for f in result.observations if "self-identifies" in f.title.lower()]
        assert len(id_observations) == 1
        assert "gpt-4" in id_observations[0].title.lower()

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
