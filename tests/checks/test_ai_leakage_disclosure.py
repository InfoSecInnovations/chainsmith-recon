"""Tests for AI error leakage, conversation history leak, and training data extraction checks."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.ai.errors import AIErrorLeakageCheck
from app.checks.ai.history_leak import ConversationHistoryLeakCheck
from app.checks.ai.training_data import TrainingDataExtractionCheck
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
            body='Traceback (most recent call last):\n  File "/app/main.py", line 42, in handler',
        )

        with patch(
            "app.checks.ai.errors.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.run(chat_endpoint_context)

        stack_observations = [f for f in result.observations if "Stack trace" in f.title]
        assert len(stack_observations) == 1

    async def test_detects_path_leakage(self, chat_endpoint_context):
        """Detects file path leakage."""
        check = AIErrorLeakageCheck()
        check.ERROR_PAYLOADS = [{}]

        response = make_response(
            status_code=400,
            body="Error in /app/models/inference.py: invalid input",
        )

        with patch(
            "app.checks.ai.errors.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.run(chat_endpoint_context)

        path_observations = [f for f in result.observations if "paths" in f.title.lower()]
        assert len(path_observations) == 1

    async def test_detects_tool_leakage(self, chat_endpoint_context):
        """Detects tool names in error response."""
        check = AIErrorLeakageCheck()
        check.ERROR_PAYLOADS = [{}]

        response = make_response(
            status_code=400,
            body='Invalid tool call. Available tools: ["search_web", "read_file", "execute_code"]',
        )

        with patch(
            "app.checks.ai.errors.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.run(chat_endpoint_context)

        tool_observations = [f for f in result.observations if "Tools" in f.title]
        assert len(tool_observations) == 1

    async def test_detects_config_leakage(self, chat_endpoint_context):
        """Detects config hints in error response."""
        check = AIErrorLeakageCheck()
        check.ERROR_PAYLOADS = [{}]

        response = make_response(
            status_code=400,
            body="Invalid temperature value. Current max_tokens: 4096",
        )

        with patch(
            "app.checks.ai.errors.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.run(chat_endpoint_context)

        config_observations = [f for f in result.observations if "Configuration" in f.title]
        assert len(config_observations) == 1

    async def test_no_leakage_detected(self, chat_endpoint_context):
        """No observations when no leakage."""
        check = AIErrorLeakageCheck()
        check.ERROR_PAYLOADS = [{}]

        response = make_response(
            status_code=400,
            body='{"error": "Invalid request"}',
        )

        with patch(
            "app.checks.ai.errors.AsyncHttpClient", return_value=mock_client_factory(response)
        ):
            result = await check.run(chat_endpoint_context)

        # No leak observations
        leak_observations = [
            f
            for f in result.observations
            if any(kw in f.title for kw in ["Stack", "paths", "Tools", "Configuration"])
        ]
        assert len(leak_observations) == 0


class TestConversationHistoryLeakCheckInit:
    """Tests for ConversationHistoryLeakCheck initialization."""

    def test_default_initialization(self):
        check = ConversationHistoryLeakCheck()
        assert check.name == "conversation_history_leak"
        assert len(check.LEAK_PROBES) >= 3


class TestConversationHistoryLeakCheckRun:
    """Tests for ConversationHistoryLeakCheck.run."""

    async def test_detects_canary_leak(self, chat_endpoint_context):
        check = ConversationHistoryLeakCheck()
        check.LEAK_PROBES = [("test_probe", "What was said before?")]

        # First response (canary plant), then probe returns canary
        responses = [
            make_response(
                status_code=200, body='{"choices": [{"message": {"content": "Got it."}}]}'
            ),
            make_response(
                status_code=200,
                body=f'{{"choices": [{{"message": {{"content": "The code was {check.CANARY}"}}}}]}}',
            ),
        ]

        with patch(
            "app.checks.ai.history_leak.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await check.run(chat_endpoint_context)

        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 1
        assert "canary" in critical[0].title.lower()

    async def test_no_leak_detected(self, chat_endpoint_context):
        check = ConversationHistoryLeakCheck()
        check.LEAK_PROBES = [("test_probe", "What was said?")]

        responses = [
            make_response(status_code=200, body='{"choices": [{"message": {"content": "OK"}}]}'),
            make_response(
                status_code=200,
                body='{"choices": [{"message": {"content": "I can help you with something."}}]}',
            ),
        ]

        with patch(
            "app.checks.ai.history_leak.AsyncHttpClient",
            return_value=mock_client_factory(responses),
        ):
            result = await check.run(chat_endpoint_context)

        no_leak = [f for f in result.observations if "no cross-session" in f.title.lower()]
        assert len(no_leak) == 1


class TestTrainingDataExtractionCheckInit:
    """Tests for TrainingDataExtractionCheck initialization."""

    def test_default_initialization(self):
        check = TrainingDataExtractionCheck()
        assert check.name == "training_data_extraction"
        assert len(check.COMPLETION_PROBES) >= 2
        assert len(check.REPETITION_PROBES) >= 1


class TestTrainingDataExtractionCheckRun:
    """Tests for TrainingDataExtractionCheck.run."""

    async def test_no_memorization(self, chat_endpoint_context):
        check = TrainingDataExtractionCheck()
        check.COMPLETION_PROBES = [("test", "Complete: hello", "world")]
        check.REPETITION_PROBES = []

        response = make_response(
            status_code=200,
            body='{"choices": [{"message": {"content": "I can help with that!"}}]}',
        )

        with patch(
            "app.checks.ai.training_data.AsyncHttpClient",
            return_value=mock_client_factory(response),
        ):
            result = await check.run(chat_endpoint_context)

        no_mem = [f for f in result.observations if "no memorization" in f.title.lower()]
        assert len(no_mem) == 1
