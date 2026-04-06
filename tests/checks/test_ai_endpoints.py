"""Tests for AI endpoint and embedding discovery checks."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.ai.endpoints import EmbeddingEndpointCheck, LLMEndpointCheck
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


class TestLLMEndpointCheckInit:
    """Tests for LLMEndpointCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = LLMEndpointCheck()

        assert check.name == "llm_endpoint_discovery"
        assert "/v1/chat/completions" in check.CHAT_PATHS
        assert "/api/generate" in check.CHAT_PATHS

    def test_metadata(self):
        """Check has educational metadata."""
        check = LLMEndpointCheck()

        assert len(check.references) > 0
        assert "Prompt Injection" in check.references[0]


class TestLLMEndpointCheckService:
    """Tests for LLMEndpointCheck.check_service."""

    async def test_discovers_chat_endpoint(self, sample_service):
        """Discovers accessible chat endpoints."""
        check = LLMEndpointCheck()
        check.CHAT_PATHS = ["/v1/chat/completions"]

        # OPTIONS returns 200, POST returns 200
        responses = [
            make_response(status_code=200),  # OPTIONS
            make_response(status_code=200, body='{"choices": []}'),  # POST
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 1
        assert "chat_endpoints" in result.outputs

    async def test_skips_404_endpoints(self, sample_service):
        """Skips endpoints that return 404."""
        check = LLMEndpointCheck()
        check.CHAT_PATHS = ["/v1/chat/completions"]

        responses = [
            make_response(status_code=200),  # OPTIONS
            make_response(status_code=404),  # POST
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 0

    async def test_detects_api_format_openai(self, sample_service):
        """Detects OpenAI API format."""
        check = LLMEndpointCheck()

        assert check._detect_api_format("/v1/chat/completions") == "openai"
        assert check._detect_api_format("/chat/completions") == "openai"

    async def test_detects_api_format_anthropic(self, sample_service):
        """Detects Anthropic API format."""
        check = LLMEndpointCheck()

        assert check._detect_api_format("/v1/messages") == "anthropic"

    async def test_detects_api_format_ollama(self, sample_service):
        """Detects Ollama API format."""
        check = LLMEndpointCheck()

        assert check._detect_api_format("/api/generate") == "ollama"
        assert check._detect_api_format("/api/chat") == "ollama"


class TestEmbeddingEndpointCheck:
    """Tests for EmbeddingEndpointCheck."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = EmbeddingEndpointCheck()

        assert check.name == "embedding_endpoint_discovery"
        assert "/v1/embeddings" in check.EMBEDDING_PATHS

    async def test_discovers_embedding_endpoint(self, sample_service):
        """Discovers accessible embedding endpoints."""
        check = EmbeddingEndpointCheck()
        check.EMBEDDING_PATHS = ["/v1/embeddings"]

        response = make_response(status_code=200, body='{"data": []}')

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.findings) == 1
        assert "embedding_endpoints" in result.outputs


class TestAIChecksIntegration:
    """Integration tests for AI checks working together."""

    async def test_endpoint_check_provides_context_for_prompt_leak(self, sample_service):
        """LLMEndpointCheck outputs feed into PromptLeakageCheck."""
        endpoint_check = LLMEndpointCheck()
        endpoint_check.CHAT_PATHS = ["/v1/chat/completions"]

        # Endpoint discovery
        responses = [
            make_response(status_code=200),  # OPTIONS
            make_response(status_code=200, body='{"choices": []}'),  # POST
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            endpoint_result = await endpoint_check.check_service(sample_service, {})

        # Verify output structure for downstream checks
        assert "chat_endpoints" in endpoint_result.outputs
        endpoints = endpoint_result.outputs["chat_endpoints"]
        assert len(endpoints) > 0
        assert "url" in endpoints[0]
        assert "service" in endpoints[0]
        assert "api_format" in endpoints[0]
