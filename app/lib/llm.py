"""
app/lib/llm.py - LLM Provider Abstraction

Supports multiple LLM backends:
  - none: No LLM (graceful degradation)
  - openai: Direct OpenAI API
  - anthropic: Direct Anthropic API
  - litellm: LiteLLM proxy (legacy SEC536 support)

Usage:
    from app.lib.llm import get_llm_client, LLMConfig

    client = get_llm_client()  # Auto-detects from env/config

    if client.is_available():
        response = await client.chat("Analyze these observations...")
    else:
        # Graceful degradation - skip LLM features
        pass
"""

from __future__ import annotations

import contextlib
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import Any

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════


class LLMProvider(Enum):
    """Supported LLM providers."""

    NONE = "none"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LITELLM = "litellm"


class LLMErrorType(StrEnum):
    """Categorized LLM error types for UI surfacing and retry decisions."""

    NONE = "none"  # No error
    RATE_LIMIT = "rate_limit"  # 429
    TIMEOUT = "timeout"  # httpx.TimeoutException
    TRANSIENT = "transient"  # 500/502/503
    CONTENT_FILTER = "content_filter"  # 400 + content policy keywords
    TOKEN_LIMIT = "token_limit"  # 400 + token/context keywords
    AUTH = "auth"  # 401/403
    NOT_CONFIGURED = "not_configured"  # NoLLMClient
    MODEL_NOT_FOUND = "model_not_found"  # 404
    PARSE_ERROR = "parse_error"  # JSON parse failure (client-side)
    UNKNOWN = "unknown"  # Unrecognized error


# Error types that are worth retrying automatically
RETRYABLE_ERROR_TYPES = {
    LLMErrorType.RATE_LIMIT,
    LLMErrorType.TIMEOUT,
    LLMErrorType.TRANSIENT,
}


@dataclass
class LLMConfig:
    """
    Provider-agnostic LLM configuration.

    Auto-detection priority:
      1. Explicit provider setting
      2. OPENAI_API_KEY present → openai
      3. ANTHROPIC_API_KEY present → anthropic
      4. LITELLM_BASE_URL present → litellm
      5. None of the above → none (disabled)
    """

    provider: LLMProvider = LLMProvider.NONE

    # OpenAI settings
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o"

    # Anthropic settings
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"

    # LiteLLM settings (legacy SEC536 support)
    litellm_base_url: str = "http://localhost:4000/v1"
    litellm_model: str = "nova-pro"
    litellm_model_fallback: str = "nova-mini"

    # Common settings
    temperature: float = 0.3
    max_tokens: int = 2000
    timeout_seconds: float = 60.0

    @classmethod
    def from_env(cls) -> LLMConfig:
        """
        Load config with priority: CLI flags (env vars) > persistent prefs > auto-detect.

        CLI flags like --no-llm and --provider set env vars before this runs.
        Persistent preferences (via `chainsmith prefs set llm.*`) are checked next.
        Auto-detection from API keys is the fallback.
        """
        cfg = cls()

        # 1. Check for explicit provider from env (set by CLI flags --no-llm / --provider)
        explicit_provider = False
        if provider_str := os.getenv("CHAINSMITH_LLM_PROVIDER", "").lower():
            try:
                cfg.provider = LLMProvider(provider_str)
                explicit_provider = True
            except ValueError:
                logger.warning(f"Unknown LLM provider: {provider_str}, using auto-detect")

        # 2. Check persistent LLM preferences (if no CLI override)
        if not explicit_provider:
            try:
                from app.preferences import load_profile_store

                store = load_profile_store()
                prefs = store.get_active_preferences()
                llm_prefs = prefs.llm

                if not llm_prefs.enabled:
                    cfg.provider = LLMProvider.NONE
                    explicit_provider = True
                    logger.info("LLM disabled via persistent preferences")
                elif llm_prefs.provider and llm_prefs.provider != "none":
                    try:
                        cfg.provider = LLMProvider(llm_prefs.provider)
                        explicit_provider = True
                        logger.info(f"LLM provider from preferences: {llm_prefs.provider}")
                    except ValueError:
                        logger.warning(f"Unknown provider in preferences: {llm_prefs.provider}")
                elif llm_prefs.provider == "none":
                    cfg.provider = LLMProvider.NONE
                    explicit_provider = True
                    logger.info("LLM disabled via persistent preferences (provider=none)")
            except Exception:
                # Preferences not available (e.g., during early startup) - continue
                pass

        # 3. Load provider-specific settings from env
        cfg.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        cfg.openai_base_url = os.getenv("OPENAI_BASE_URL", cfg.openai_base_url)
        cfg.openai_model = os.getenv("OPENAI_MODEL", cfg.openai_model)

        cfg.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")
        cfg.anthropic_model = os.getenv("ANTHROPIC_MODEL", cfg.anthropic_model)

        cfg.litellm_base_url = os.getenv("LITELLM_BASE_URL", cfg.litellm_base_url)
        cfg.litellm_model = os.getenv("LITELLM_MODEL_CHAINSMITH", cfg.litellm_model)
        cfg.litellm_model_fallback = os.getenv(
            "LITELLM_MODEL_CHAINSMITH_FALLBACK", cfg.litellm_model_fallback
        )

        # Common settings
        if temp := os.getenv("CHAINSMITH_LLM_TEMPERATURE"):
            with contextlib.suppress(ValueError):
                cfg.temperature = float(temp)

        if tokens := os.getenv("CHAINSMITH_LLM_MAX_TOKENS"):
            with contextlib.suppress(ValueError):
                cfg.max_tokens = int(tokens)

        # 4. Auto-detect provider if nothing was explicitly set
        if not explicit_provider:
            cfg.provider = cfg._auto_detect_provider()

        return cfg

    def _auto_detect_provider(self) -> LLMProvider:
        """Auto-detect provider based on available credentials."""
        if self.openai_api_key:
            logger.info("Auto-detected LLM provider: openai")
            return LLMProvider.OPENAI
        if self.anthropic_api_key:
            logger.info("Auto-detected LLM provider: anthropic")
            return LLMProvider.ANTHROPIC
        if self.litellm_base_url and self.litellm_base_url != "http://localhost:4000/v1":
            logger.info("Auto-detected LLM provider: litellm")
            return LLMProvider.LITELLM

        logger.info("No LLM provider configured - chain analysis will be skipped")
        return LLMProvider.NONE


# ═══════════════════════════════════════════════════════════════════════════════
# Client Interface
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class LLMResponse:
    """Response from an LLM call."""

    content: str
    model: str
    provider: str
    success: bool = True
    error: str | None = None
    error_type: LLMErrorType = LLMErrorType.NONE
    retryable: bool = False
    usage: dict = field(default_factory=dict)


def _classify_error(
    status_code: int, body: str, exception: Exception | None = None
) -> tuple[LLMErrorType, bool]:
    """
    Classify an LLM error by HTTP status and response body.

    Returns (error_type, retryable).
    """
    if exception is not None:
        exc_name = type(exception).__name__
        if "Timeout" in exc_name or "TimeoutException" in exc_name:
            return LLMErrorType.TIMEOUT, True
        if status_code == 0:
            return LLMErrorType.TRANSIENT, True

    if status_code == 429:
        return LLMErrorType.RATE_LIMIT, True

    if status_code in (500, 502, 503):
        return LLMErrorType.TRANSIENT, True

    if status_code in (401, 403):
        return LLMErrorType.AUTH, False

    if status_code == 404:
        return LLMErrorType.MODEL_NOT_FOUND, False

    if status_code == 400:
        lower = body.lower()
        content_kw = (
            "content policy",
            "safety",
            "moderation",
            "content filter",
            "harmful",
            "refused",
            "not allowed",
        )
        if any(kw in lower for kw in content_kw):
            return LLMErrorType.CONTENT_FILTER, False

        token_kw = (
            "token",
            "context length",
            "context_length",
            "maximum context",
            "too long",
            "too many tokens",
        )
        if any(kw in lower for kw in token_kw):
            return LLMErrorType.TOKEN_LIMIT, False

    return LLMErrorType.UNKNOWN, False


class LLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(self, config: LLMConfig):
        self.config = config

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this provider is configured and available."""
        pass

    @abstractmethod
    async def chat(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a chat message and get a response."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name."""
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# Provider Implementations
# ═══════════════════════════════════════════════════════════════════════════════


class NoLLMClient(LLMClient):
    """Null client for when no LLM is configured."""

    def is_available(self) -> bool:
        return False

    async def chat(self, prompt: str, **kwargs) -> LLMResponse:
        return LLMResponse(
            content="",
            model="none",
            provider="none",
            success=False,
            error="No LLM provider configured",
            error_type=LLMErrorType.NOT_CONFIGURED,
            retryable=False,
        )

    @property
    def provider_name(self) -> str:
        return "none"


class OpenAIClient(LLMClient):
    """OpenAI API client."""

    def is_available(self) -> bool:
        return bool(self.config.openai_api_key)

    async def chat(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        try:
            import httpx
        except ImportError:
            return LLMResponse(
                content="",
                model=self.config.openai_model,
                provider="openai",
                success=False,
                error="httpx not installed",
            )

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(
                    f"{self.config.openai_base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.config.openai_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.config.openai_model,
                        "messages": messages,
                        "temperature": temperature or self.config.temperature,
                        "max_tokens": max_tokens or self.config.max_tokens,
                    },
                )

                if response.status_code != 200:
                    error_type, retryable = _classify_error(
                        response.status_code, response.text[:500]
                    )
                    return LLMResponse(
                        content="",
                        model=self.config.openai_model,
                        provider="openai",
                        success=False,
                        error=f"HTTP {response.status_code}: {response.text[:200]}",
                        error_type=error_type,
                        retryable=retryable,
                    )

                data = response.json()
                return LLMResponse(
                    content=data["choices"][0]["message"]["content"],
                    model=data.get("model", self.config.openai_model),
                    provider="openai",
                    success=True,
                    usage=data.get("usage", {}),
                )

        except Exception as e:
            error_type, retryable = _classify_error(0, str(e), exception=e)
            return LLMResponse(
                content="",
                model=self.config.openai_model,
                provider="openai",
                success=False,
                error=str(e),
                error_type=error_type,
                retryable=retryable,
            )

    @property
    def provider_name(self) -> str:
        return "openai"


class AnthropicClient(LLMClient):
    """Anthropic API client."""

    def is_available(self) -> bool:
        return bool(self.config.anthropic_api_key)

    async def chat(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        try:
            import httpx
        except ImportError:
            return LLMResponse(
                content="",
                model=self.config.anthropic_model,
                provider="anthropic",
                success=False,
                error="httpx not installed",
            )

        messages = [{"role": "user", "content": prompt}]

        body: dict[str, Any] = {
            "model": self.config.anthropic_model,
            "messages": messages,
            "max_tokens": max_tokens or self.config.max_tokens,
        }

        if system:
            body["system"] = system

        # Anthropic doesn't support temperature=0, minimum is 0.0 but we use 0.1
        temp = temperature or self.config.temperature
        if temp > 0:
            body["temperature"] = temp

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.config.anthropic_api_key,
                        "Content-Type": "application/json",
                        "anthropic-version": "2023-06-01",
                    },
                    json=body,
                )

                if response.status_code != 200:
                    error_type, retryable = _classify_error(
                        response.status_code, response.text[:500]
                    )
                    return LLMResponse(
                        content="",
                        model=self.config.anthropic_model,
                        provider="anthropic",
                        success=False,
                        error=f"HTTP {response.status_code}: {response.text[:200]}",
                        error_type=error_type,
                        retryable=retryable,
                    )

                data = response.json()
                content = ""
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        content += block.get("text", "")

                return LLMResponse(
                    content=content,
                    model=data.get("model", self.config.anthropic_model),
                    provider="anthropic",
                    success=True,
                    usage=data.get("usage", {}),
                )

        except Exception as e:
            error_type, retryable = _classify_error(0, str(e), exception=e)
            return LLMResponse(
                content="",
                model=self.config.anthropic_model,
                provider="anthropic",
                success=False,
                error=str(e),
                error_type=error_type,
                retryable=retryable,
            )

    @property
    def provider_name(self) -> str:
        return "anthropic"


class LiteLLMClient(LLMClient):
    """LiteLLM proxy client (legacy SEC536 support)."""

    def is_available(self) -> bool:
        return bool(self.config.litellm_base_url)

    async def chat(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        try:
            import httpx
        except ImportError:
            return LLMResponse(
                content="",
                model=self.config.litellm_model,
                provider="litellm",
                success=False,
                error="httpx not installed",
            )

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        models_to_try = [self.config.litellm_model]
        if self.config.litellm_model_fallback:
            models_to_try.append(self.config.litellm_model_fallback)

        last_error = ""
        last_status = 0

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                for model in models_to_try:
                    response = await client.post(
                        f"{self.config.litellm_base_url}/chat/completions",
                        json={
                            "model": model,
                            "messages": messages,
                            "temperature": temperature or self.config.temperature,
                            "max_tokens": max_tokens or self.config.max_tokens,
                        },
                    )

                    if response.status_code == 200:
                        data = response.json()
                        return LLMResponse(
                            content=data["choices"][0]["message"]["content"],
                            model=data.get("model", model),
                            provider="litellm",
                            success=True,
                            usage=data.get("usage", {}),
                        )

                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    last_status = response.status_code
                    logger.warning(f"LiteLLM model {model} failed: {last_error}")

                error_type, retryable = _classify_error(last_status, last_error)
                return LLMResponse(
                    content="",
                    model=self.config.litellm_model,
                    provider="litellm",
                    success=False,
                    error=last_error,
                    error_type=error_type,
                    retryable=retryable,
                )

        except Exception as e:
            error_type, retryable = _classify_error(0, str(e), exception=e)
            return LLMResponse(
                content="",
                model=self.config.litellm_model,
                provider="litellm",
                success=False,
                error=str(e),
                error_type=error_type,
                retryable=retryable,
            )

    @property
    def provider_name(self) -> str:
        return "litellm"


# ═══════════════════════════════════════════════════════════════════════════════
# Factory
# ═══════════════════════════════════════════════════════════════════════════════


_cached_client: LLMClient | None = None


def get_llm_client(config: LLMConfig | None = None, reload: bool = False) -> LLMClient:
    """
    Get an LLM client instance.

    Auto-detects provider from environment if config not provided.
    Result is cached for efficiency.

    Args:
        config: Optional explicit configuration
        reload: Force re-creation of client

    Returns:
        LLMClient instance (may be NoLLMClient if no provider configured)
    """
    global _cached_client

    _explicit_config = config is not None

    if _cached_client is not None and not reload and not _explicit_config:
        return _cached_client

    if config is None:
        config = LLMConfig.from_env()

    client: LLMClient

    if config.provider == LLMProvider.OPENAI:
        client = OpenAIClient(config)
    elif config.provider == LLMProvider.ANTHROPIC:
        client = AnthropicClient(config)
    elif config.provider == LLMProvider.LITELLM:
        client = LiteLLMClient(config)
    else:
        client = NoLLMClient(config)

    if not _explicit_config:  # Only cache auto-detected config
        _cached_client = client

    return client


def reset_llm_client() -> None:
    """Clear cached LLM client (useful for testing)."""
    global _cached_client
    _cached_client = None
