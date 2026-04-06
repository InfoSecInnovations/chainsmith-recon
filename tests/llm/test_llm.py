"""
Tests for app/lib/llm.py

Covers:
- LLMConfig loading and auto-detection
- LLMProvider enum
- NoLLMClient (graceful degradation)
- OpenAIClient
- AnthropicClient
- LiteLLMClient
- get_llm_client factory
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.lib.llm import (
    AnthropicClient,
    LiteLLMClient,
    LLMConfig,
    LLMProvider,
    NoLLMClient,
    OpenAIClient,
    get_llm_client,
    reset_llm_client,
)


pytestmark = pytest.mark.unit

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def reset_client():
    """Reset cached client before each test."""
    reset_llm_client()
    yield
    reset_llm_client()


@pytest.fixture
def clean_env(monkeypatch):
    """Clean environment of LLM-related variables."""
    for key in list(os.environ.keys()):
        if any(x in key for x in ["OPENAI", "ANTHROPIC", "LITELLM", "CHAINSMITH_LLM"]):
            monkeypatch.delenv(key, raising=False)
    return monkeypatch


# ═══════════════════════════════════════════════════════════════════════════════
# LLMProvider Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestLLMProvider:
    """Tests for LLMProvider enum."""

    def test_provider_values(self):
        """Provider enum has expected values."""
        assert LLMProvider.NONE.value == "none"
        assert LLMProvider.OPENAI.value == "openai"
        assert LLMProvider.ANTHROPIC.value == "anthropic"
        assert LLMProvider.LITELLM.value == "litellm"

    def test_provider_from_string(self):
        """Provider can be created from string."""
        assert LLMProvider("none") == LLMProvider.NONE
        assert LLMProvider("openai") == LLMProvider.OPENAI


# ═══════════════════════════════════════════════════════════════════════════════
# LLMConfig Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestLLMConfig:
    """Tests for LLMConfig."""

    def test_default_config(self):
        """Default config has sensible values."""
        cfg = LLMConfig()

        assert cfg.provider == LLMProvider.NONE
        assert cfg.openai_model == "gpt-4o"
        assert cfg.anthropic_model == "claude-sonnet-4-20250514"
        assert cfg.temperature == 0.3
        assert cfg.max_tokens == 2000

    def test_from_env_no_credentials(self, clean_env):
        """from_env with no credentials returns NONE provider."""
        cfg = LLMConfig.from_env()

        assert cfg.provider == LLMProvider.NONE

    def test_from_env_openai_key(self, clean_env):
        """from_env auto-detects OpenAI from API key."""
        clean_env.setenv("OPENAI_API_KEY", "sk-test-key")

        cfg = LLMConfig.from_env()

        assert cfg.provider == LLMProvider.OPENAI
        assert cfg.openai_api_key == "sk-test-key"

    def test_from_env_anthropic_key(self, clean_env):
        """from_env auto-detects Anthropic from API key."""
        clean_env.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

        cfg = LLMConfig.from_env()

        assert cfg.provider == LLMProvider.ANTHROPIC
        assert cfg.anthropic_api_key == "sk-ant-test"

    def test_from_env_explicit_provider(self, clean_env):
        """Explicit provider overrides auto-detection."""
        clean_env.setenv("OPENAI_API_KEY", "sk-test")
        clean_env.setenv("CHAINSMITH_LLM_PROVIDER", "none")

        cfg = LLMConfig.from_env()

        assert cfg.provider == LLMProvider.NONE

    def test_from_env_litellm(self, clean_env):
        """from_env detects LiteLLM from non-default base URL."""
        clean_env.setenv("LITELLM_BASE_URL", "http://my-proxy:4000/v1")

        cfg = LLMConfig.from_env()

        assert cfg.provider == LLMProvider.LITELLM

    def test_from_env_custom_settings(self, clean_env):
        """from_env loads custom settings."""
        clean_env.setenv("OPENAI_API_KEY", "sk-test")
        clean_env.setenv("OPENAI_MODEL", "gpt-4-turbo")
        clean_env.setenv("CHAINSMITH_LLM_TEMPERATURE", "0.7")
        clean_env.setenv("CHAINSMITH_LLM_MAX_TOKENS", "4000")

        cfg = LLMConfig.from_env()

        assert cfg.openai_model == "gpt-4-turbo"
        assert cfg.temperature == 0.7
        assert cfg.max_tokens == 4000


# ═══════════════════════════════════════════════════════════════════════════════
# NoLLMClient Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestNoLLMClient:
    """Tests for NoLLMClient (graceful degradation)."""

    def test_is_not_available(self):
        """NoLLMClient is never available."""
        client = NoLLMClient(LLMConfig())
        assert client.is_available() is False

    async def test_chat_returns_error(self):
        """NoLLMClient.chat returns error response."""
        client = NoLLMClient(LLMConfig())

        response = await client.chat("Hello")

        assert response.success is False
        assert "No LLM provider configured" in response.error
        assert response.provider == "none"

    def test_provider_name(self):
        """NoLLMClient has correct provider name."""
        client = NoLLMClient(LLMConfig())
        assert client.provider_name == "none"


# ═══════════════════════════════════════════════════════════════════════════════
# OpenAIClient Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestOpenAIClient:
    """Tests for OpenAIClient."""

    def test_is_available_with_key(self):
        """OpenAIClient is available when API key present."""
        cfg = LLMConfig(openai_api_key="sk-test")
        client = OpenAIClient(cfg)

        assert client.is_available() is True

    def test_is_not_available_without_key(self):
        """OpenAIClient is not available without API key."""
        cfg = LLMConfig()
        client = OpenAIClient(cfg)

        assert client.is_available() is False

    async def test_chat_success(self):
        """OpenAIClient.chat returns successful response."""
        cfg = LLMConfig(openai_api_key="sk-test")
        client = OpenAIClient(cfg)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Hello!"}}],
            "model": "gpt-4o",
            "usage": {"total_tokens": 10},
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock()
            mock_client.return_value.post = AsyncMock(return_value=mock_response)

            response = await client.chat("Hi")

        assert response.success is True
        assert response.content == "Hello!"
        assert response.provider == "openai"

    async def test_chat_with_system_prompt(self):
        """OpenAIClient.chat includes system prompt."""
        cfg = LLMConfig(openai_api_key="sk-test")
        client = OpenAIClient(cfg)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Response"}}],
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock()
            mock_client.return_value.post = AsyncMock(return_value=mock_response)

            await client.chat("Hi", system="You are helpful")

            # Check that system message was included
            call_args = mock_client.return_value.post.call_args
            messages = call_args[1]["json"]["messages"]
            assert messages[0]["role"] == "system"

    async def test_chat_error(self):
        """OpenAIClient.chat handles errors."""
        cfg = LLMConfig(openai_api_key="sk-test")
        client = OpenAIClient(cfg)

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Invalid API key"

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock()
            mock_client.return_value.post = AsyncMock(return_value=mock_response)

            response = await client.chat("Hi")

        assert response.success is False
        assert "401" in response.error


# ═══════════════════════════════════════════════════════════════════════════════
# AnthropicClient Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnthropicClient:
    """Tests for AnthropicClient."""

    def test_is_available_with_key(self):
        """AnthropicClient is available when API key present."""
        cfg = LLMConfig(anthropic_api_key="sk-ant-test")
        client = AnthropicClient(cfg)

        assert client.is_available() is True

    async def test_chat_success(self):
        """AnthropicClient.chat returns successful response."""
        cfg = LLMConfig(anthropic_api_key="sk-ant-test")
        client = AnthropicClient(cfg)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "content": [{"type": "text", "text": "Hello from Claude!"}],
            "model": "claude-sonnet-4-20250514",
            "usage": {"input_tokens": 5, "output_tokens": 5},
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock()
            mock_client.return_value.post = AsyncMock(return_value=mock_response)

            response = await client.chat("Hi")

        assert response.success is True
        assert response.content == "Hello from Claude!"
        assert response.provider == "anthropic"


# ═══════════════════════════════════════════════════════════════════════════════
# LiteLLMClient Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestLiteLLMClient:
    """Tests for LiteLLMClient."""

    def test_is_available_with_url(self):
        """LiteLLMClient is available when base URL set."""
        cfg = LLMConfig(litellm_base_url="http://proxy:4000/v1")
        client = LiteLLMClient(cfg)

        assert client.is_available() is True

    async def test_chat_with_fallback(self):
        """LiteLLMClient tries fallback model on failure."""
        cfg = LLMConfig(
            litellm_base_url="http://proxy:4000/v1",
            litellm_model="primary",
            litellm_model_fallback="fallback",
        )
        client = LiteLLMClient(cfg)

        call_count = 0

        def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            if call_count == 1:
                mock_resp.status_code = 500
                mock_resp.text = "Error"
            else:
                mock_resp.status_code = 200
                mock_resp.json.return_value = {
                    "choices": [{"message": {"content": "Fallback response"}}],
                }
            return mock_resp

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock()
            mock_client.return_value.post = AsyncMock(side_effect=mock_post)

            response = await client.chat("Hi")

        assert response.success is True
        assert call_count == 2  # Primary failed, fallback succeeded


# ═══════════════════════════════════════════════════════════════════════════════
# Factory Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetLLMClient:
    """Tests for get_llm_client factory."""

    def test_returns_no_llm_by_default(self, clean_env):
        """get_llm_client returns NoLLMClient when no config."""
        client = get_llm_client()

        assert isinstance(client, NoLLMClient)
        assert client.is_available() is False

    def test_returns_openai_with_key(self, clean_env):
        """get_llm_client returns OpenAIClient with API key."""
        clean_env.setenv("OPENAI_API_KEY", "sk-test")

        client = get_llm_client(reload=True)

        assert isinstance(client, OpenAIClient)

    def test_returns_anthropic_with_key(self, clean_env):
        """get_llm_client returns AnthropicClient with API key."""
        clean_env.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

        client = get_llm_client(reload=True)

        assert isinstance(client, AnthropicClient)

    def test_explicit_config(self, clean_env):
        """get_llm_client uses explicit config."""
        cfg = LLMConfig(
            provider=LLMProvider.OPENAI,
            openai_api_key="sk-explicit",
        )

        client = get_llm_client(config=cfg)

        assert isinstance(client, OpenAIClient)

    def test_caching(self, clean_env):
        """get_llm_client caches result."""
        client1 = get_llm_client()
        client2 = get_llm_client()

        assert client1 is client2

    def test_reload_clears_cache(self, clean_env):
        """get_llm_client with reload=True creates new client."""
        client1 = get_llm_client()
        client2 = get_llm_client(reload=True)

        assert client1 is not client2
