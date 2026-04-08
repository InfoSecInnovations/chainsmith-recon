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


class TestLLMEndpointCheckService:
    """Tests for LLMEndpointCheck.check_service."""

    async def test_discovers_chat_endpoint_with_correct_observation(self, sample_service):
        """Discovers accessible chat endpoints with correct title, severity, and evidence."""
        check = LLMEndpointCheck()
        check.CHAT_PATHS = ["/v1/chat/completions"]

        responses = [
            make_response(status_code=200),  # OPTIONS
            make_response(status_code=200, body='{"choices": []}'),  # POST
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "LLM endpoint: /v1/chat/completions"
        assert obs.severity == "info"
        assert obs.description == "Chat/completion endpoint discovered (openai format)"
        assert "POST /v1/chat/completions -> HTTP 200" in obs.evidence
        assert "format: openai" in obs.evidence
        assert obs.target_url == "http://ai.example.com:8080/v1/chat/completions"
        assert obs.check_name == "llm_endpoint_discovery"

        # Verify outputs structure
        assert "chat_endpoints" in result.outputs
        endpoints = result.outputs["chat_endpoints"]
        assert len(endpoints) == 1
        assert endpoints[0]["url"] == "http://ai.example.com:8080/v1/chat/completions"
        assert endpoints[0]["path"] == "/v1/chat/completions"
        assert endpoints[0]["api_format"] == "openai"
        assert endpoints[0]["status_code"] == 200
        assert endpoints[0]["service"]["host"] == "ai.example.com"

    async def test_skips_404_on_post(self, sample_service):
        """POST returning 404 produces no observations and no outputs."""
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

        assert len(result.observations) == 0
        assert "chat_endpoints" not in result.outputs

    async def test_skips_405_on_post(self, sample_service):
        """POST returning 405 Method Not Allowed produces no observations."""
        check = LLMEndpointCheck()
        check.CHAT_PATHS = ["/v1/chat/completions"]

        responses = [
            make_response(status_code=200),  # OPTIONS
            make_response(status_code=405),  # POST
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 0
        assert "chat_endpoints" not in result.outputs

    async def test_skips_when_options_returns_500(self, sample_service):
        """OPTIONS returning 500 causes the path to be skipped entirely."""
        check = LLMEndpointCheck()
        check.CHAT_PATHS = ["/v1/chat/completions"]

        responses = [
            make_response(status_code=500),  # OPTIONS - server error
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 0
        assert "chat_endpoints" not in result.outputs

    async def test_skips_when_options_has_error(self, sample_service):
        """OPTIONS returning a connection error causes the path to be skipped."""
        check = LLMEndpointCheck()
        check.CHAT_PATHS = ["/v1/chat/completions"]

        responses = [
            make_response(status_code=0, error="Connection refused"),  # OPTIONS error
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 0
        assert "chat_endpoints" not in result.outputs

    async def test_non_ai_response_on_chat_path_still_produces_observation(self, sample_service):
        """A non-AI JSON body (e.g. generic HTML/error) on a chat path still registers
        because the check keys on status code, not response content."""
        check = LLMEndpointCheck()
        check.CHAT_PATHS = ["/v1/chat/completions"]

        responses = [
            make_response(status_code=200),  # OPTIONS
            make_response(
                status_code=200,
                body='{"error": "unknown route"}',
            ),  # POST - non-AI body
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        # The check does NOT inspect response bodies -- any 200 on the path is recorded.
        # This is a known design choice; the observation is still produced.
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "LLM endpoint: /v1/chat/completions"
        assert obs.severity == "info"

    async def test_discovers_multiple_paths(self, sample_service):
        """Multiple accessible paths each produce their own observation."""
        check = LLMEndpointCheck()
        check.CHAT_PATHS = ["/v1/chat/completions", "/api/generate"]

        responses = [
            make_response(status_code=200),  # OPTIONS for path 1
            make_response(status_code=200, body='{"choices": []}'),  # POST for path 1
            make_response(status_code=200),  # OPTIONS for path 2
            make_response(status_code=200, body='{"response": "hi"}'),  # POST for path 2
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 2
        titles = [obs.title for obs in result.observations]
        assert "LLM endpoint: /v1/chat/completions" in titles
        assert "LLM endpoint: /api/generate" in titles

        # Verify different formats detected
        formats = {obs.title: obs.description for obs in result.observations}
        assert "openai" in formats["LLM endpoint: /v1/chat/completions"]
        assert "ollama" in formats["LLM endpoint: /api/generate"]

        assert len(result.outputs["chat_endpoints"]) == 2

    async def test_post_error_skips_endpoint(self, sample_service):
        """POST returning a connection error skips the endpoint."""
        check = LLMEndpointCheck()
        check.CHAT_PATHS = ["/v1/chat/completions"]

        responses = [
            make_response(status_code=200),  # OPTIONS OK
            make_response(status_code=0, error="Connection reset"),  # POST error
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 0
        assert "chat_endpoints" not in result.outputs

    async def test_401_on_post_still_produces_observation(self, sample_service):
        """A 401 Unauthorized is NOT filtered out -- endpoint exists but requires auth."""
        check = LLMEndpointCheck()
        check.CHAT_PATHS = ["/v1/chat/completions"]

        responses = [
            make_response(status_code=200),  # OPTIONS
            make_response(status_code=401, body='{"error": "unauthorized"}'),  # POST
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "LLM endpoint: /v1/chat/completions"
        assert "HTTP 401" in obs.evidence


class TestDetectApiFormat:
    """Tests for LLMEndpointCheck._detect_api_format with full path coverage."""

    def setup_method(self):
        self.check = LLMEndpointCheck()

    def test_openai_v1_chat_completions(self):
        assert self.check._detect_api_format("/v1/chat/completions") == "openai"

    def test_openai_chat_completions_without_v1(self):
        assert self.check._detect_api_format("/chat/completions") == "openai"

    def test_anthropic_messages(self):
        assert self.check._detect_api_format("/v1/messages") == "anthropic"

    def test_anthropic_messages_without_v1(self):
        assert self.check._detect_api_format("/messages") == "anthropic"

    def test_ollama_generate(self):
        assert self.check._detect_api_format("/api/generate") == "ollama"

    def test_ollama_chat(self):
        assert self.check._detect_api_format("/api/chat") == "ollama"

    def test_langserve_invoke(self):
        assert self.check._detect_api_format("/invoke") == "langserve"

    def test_langserve_stream(self):
        assert self.check._detect_api_format("/stream") == "langserve"

    def test_tgi_generate(self):
        """Paths containing 'generate' but not matching ollama fall through to tgi."""
        assert self.check._detect_api_format("/generate") == "tgi"
        assert self.check._detect_api_format("/v1/generate") == "tgi"
        assert self.check._detect_api_format("/generate_stream") == "tgi"

    def test_unknown_path(self):
        assert self.check._detect_api_format("/predict") == "unknown"
        assert self.check._detect_api_format("/batch") == "unknown"
        assert self.check._detect_api_format("/inference") == "unknown"

    def test_case_insensitive(self):
        """Detection is case-insensitive."""
        assert self.check._detect_api_format("/V1/Chat/Completions") == "openai"
        assert self.check._detect_api_format("/API/GENERATE") == "ollama"


class TestEmbeddingEndpointCheck:
    """Tests for EmbeddingEndpointCheck."""

    async def test_discovers_embedding_endpoint_with_correct_observation(self, sample_service):
        """Discovers accessible embedding endpoint with correct title, severity, evidence."""
        check = EmbeddingEndpointCheck()
        check.EMBEDDING_PATHS = ["/v1/embeddings"]

        response = make_response(status_code=200, body='{"data": []}')

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Embedding endpoint: /v1/embeddings"
        assert obs.severity == "info"
        assert obs.description == "Embedding/vector endpoint discovered"
        assert "POST /v1/embeddings -> HTTP 200" in obs.evidence
        assert obs.target_url == "http://ai.example.com:8080/v1/embeddings"
        assert obs.check_name == "embedding_endpoint_discovery"

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
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 0
        assert "embedding_endpoints" not in result.outputs

    async def test_skips_405_embedding_endpoint(self, sample_service):
        """POST returning 405 on embedding path produces no observations."""
        check = EmbeddingEndpointCheck()
        check.EMBEDDING_PATHS = ["/v1/embeddings"]

        response = make_response(status_code=405)

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 0
        assert "embedding_endpoints" not in result.outputs

    async def test_skips_embedding_on_error(self, sample_service):
        """Connection error on embedding path produces no observations."""
        check = EmbeddingEndpointCheck()
        check.EMBEDDING_PATHS = ["/v1/embeddings"]

        response = make_response(status_code=0, error="Timeout")

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 0
        assert "embedding_endpoints" not in result.outputs

    async def test_non_ai_body_on_embedding_path_still_registers(self, sample_service):
        """Non-embedding JSON on an embedding path still produces an observation
        because the check does not inspect response body content."""
        check = EmbeddingEndpointCheck()
        check.EMBEDDING_PATHS = ["/v1/embeddings"]

        response = make_response(status_code=200, body='{"message": "not found"}')

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.check_service(sample_service, {})

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "Embedding endpoint: /v1/embeddings"
        assert obs.severity == "info"


class TestAIChecksIntegration:
    """Integration tests for AI checks working together."""

    async def test_endpoint_check_output_structure_for_downstream(self, sample_service):
        """LLMEndpointCheck outputs contain all fields needed by downstream checks."""
        endpoint_check = LLMEndpointCheck()
        endpoint_check.CHAT_PATHS = ["/v1/chat/completions"]

        responses = [
            make_response(status_code=200),  # OPTIONS
            make_response(status_code=200, body='{"choices": []}'),  # POST
        ]

        with patch(
            "app.checks.ai.endpoints.AsyncHttpClient", return_value=mock_client_factory(responses)
        ):
            endpoint_result = await endpoint_check.check_service(sample_service, {})

        assert "chat_endpoints" in endpoint_result.outputs
        endpoints = endpoint_result.outputs["chat_endpoints"]
        assert len(endpoints) == 1

        ep = endpoints[0]
        assert ep["url"] == "http://ai.example.com:8080/v1/chat/completions"
        assert ep["path"] == "/v1/chat/completions"
        assert ep["api_format"] == "openai"
        assert ep["status_code"] == 200
        assert ep["service"]["host"] == "ai.example.com"
        assert ep["service"]["port"] == 8080
