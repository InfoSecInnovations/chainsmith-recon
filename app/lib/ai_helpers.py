"""
app/lib/ai_helpers.py - AI Check Utilities

Shared helpers for AI suite checks:
- Request formatting per API dialect (OpenAI, Ollama, generic)
- Response text extraction per API dialect
- Common AI-specific evidence formatters
"""

from typing import Any

# ── API dialects ──────────────────────────────────────────────────


def format_chat_request(message: str, api_format: str, max_tokens: int = 50) -> dict:
    """
    Format a chat request body for the given API dialect.

    Supported formats: openai, anthropic, ollama, generic
    Falls back to a generic {"message": ...} envelope for unknowns.
    """
    if api_format == "openai":
        return {
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": message}],
            "max_tokens": max_tokens,
        }
    elif api_format == "anthropic":
        return {
            "model": "claude-3-haiku-20240307",
            "messages": [{"role": "user", "content": message}],
            "max_tokens": max_tokens,
        }
    elif api_format == "ollama":
        return {"model": "llama2", "prompt": message}
    else:
        return {"message": message}


def extract_response_text(body: Any, api_format: str) -> str:
    """
    Extract the assistant's text from a chat response body.

    Returns empty string if extraction fails rather than raising.
    """
    if not isinstance(body, dict):
        return str(body) if body else ""

    if api_format == "openai":
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            pass

    elif api_format == "anthropic":
        try:
            return body["content"][0]["text"]
        except (KeyError, IndexError, TypeError):
            pass

    elif api_format == "ollama":
        return body.get("response", "")

    # Generic fallback: try common response field names
    for field in ("response", "message", "content", "text", "output", "generated_text"):
        val = body.get(field)
        if isinstance(val, str):
            return val

    return str(body)


# ── Evidence formatters ───────────────────────────────────────────


def format_chat_request_with_system(
    message: str,
    system: str,
    api_format: str,
    max_tokens: int = 50,
    **extra_params,
) -> dict:
    """
    Format a chat request with an explicit system message.

    Extra keyword arguments are merged into the top-level body
    (e.g. temperature=2.0, tools=[...]).
    """
    if api_format == "openai":
        body = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": message},
            ],
            "max_tokens": max_tokens,
        }
    elif api_format == "anthropic":
        body = {
            "model": "claude-3-haiku-20240307",
            "system": system,
            "messages": [{"role": "user", "content": message}],
            "max_tokens": max_tokens,
        }
    elif api_format == "ollama":
        body = {"model": "llama2", "prompt": message, "system": system}
    else:
        body = {"message": message, "system": system}

    body.update(extra_params)
    return body


def format_chat_request_with_extra(
    message: str,
    api_format: str,
    max_tokens: int = 50,
    **extra_params,
) -> dict:
    """
    Format a standard chat request with extra top-level parameters merged in.
    """
    body = format_chat_request(message, api_format, max_tokens)
    body.update(extra_params)
    return body


def format_multiturn_request(
    messages: list[dict],
    api_format: str,
    max_tokens: int = 50,
) -> dict:
    """
    Format a multi-turn chat request from a list of
    {role, content} dicts.
    """
    if api_format == "openai":
        return {
            "model": "gpt-3.5-turbo",
            "messages": messages,
            "max_tokens": max_tokens,
        }
    elif api_format == "anthropic":
        return {
            "model": "claude-3-haiku-20240307",
            "messages": messages,
            "max_tokens": max_tokens,
        }
    elif api_format == "ollama":
        # Ollama doesn't support multi-turn natively; concat as prompt
        prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages)
        return {"model": "llama2", "prompt": prompt}
    else:
        prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages)
        return {"message": prompt}


def fmt_endpoint_probe_evidence(path: str, status_code: int, api_format: str = "") -> str:
    parts = [f"POST {path} -> HTTP {status_code}"]
    if api_format and api_format != "unknown":
        parts.append(f"format: {api_format}")
    return " | ".join(parts)


def fmt_rate_limit_evidence(request_count: int, status_code: int, headers: dict) -> str:
    base = f"{request_count} requests -> HTTP {status_code}"
    if headers:
        header_str = ", ".join(f"{k}: {v}" for k, v in list(headers.items())[:3])
        return f"{base} | Rate limit headers: {header_str}"
    return base


def fmt_filter_evidence(blocked: list[str], allowed: list[str]) -> str:
    parts = []
    if blocked:
        parts.append(f"Blocked: {', '.join(blocked)}")
    if allowed:
        parts.append(f"Allowed: {', '.join(allowed)}")
    return " | ".join(parts) if parts else "No filter activity detected"


def fmt_context_evidence(max_successful: int, failed_at: int | None, error_type: str | None) -> str:
    base = f"Max successful: ~{max_successful} tokens"
    if failed_at:
        base += f", failed at ~{failed_at} tokens"
    if error_type:
        base += f" ({error_type})"
    return base
