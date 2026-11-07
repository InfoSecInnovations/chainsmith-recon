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


# ── Reading a recorded request back ───────────
#
# The AI suite's probe/grade split needs the inverse of the formatters above.
# A probe sends N payloads down one endpoint and records N exchanges; the
# grader then has to know *which payload* produced the response it is looking
# at, because for almost every check in the suite the judgement is "did the
# target comply with THIS prompt's intent". Pairing the stored exchanges
# positionally against the list the probe happened to send would reintroduce
# exactly the drift the web suite hit when its mocks stamped one URL onto every
# response: two representations of the question, one of which is a guess.
#
# So the payload is read back off `Exchange.request_body`, the way the web
# suite reads the path back off `Exchange.request_url`. That is the ai analogue
# of §0.13's rule, and it is what makes the double parse of §6.2 safe here.


def messages_from_request(request_body: str) -> list[dict]:
    """Every turn a recorded chat request carried, as `{role, content}` dicts.

    The inverse of `format_chat_request` / `format_multiturn_request` /
    `format_chat_request_with_system`, across all four dialects — and it takes
    no `api_format`, unlike the formatters and unlike `extract_response_text`,
    because a recorded *request* body is self-describing: `messages` is the
    OpenAI/Anthropic shape, `prompt` is Ollama's, `message` the generic
    envelope. The dialect is only needed on the response side, where the three
    carry the answer under three different keys at three different depths.
    Ollama and the
    generic envelope collapse a conversation into one string (see
    `format_multiturn_request`), so a multi-turn request recorded in those
    dialects comes back as the `role: content` lines it was flattened into —
    which is all the target ever saw of the structure.

    Returns `[]` rather than raising when the body is absent or not JSON: a
    grader reading a failed or unrecorded exchange gets an empty conversation,
    not an exception.
    """
    from app.lib.parsing import safe_json

    body = safe_json(request_body or "")
    if not isinstance(body, dict):
        return []

    messages = body.get("messages")
    if isinstance(messages, list):
        turns = [
            {"role": str(m.get("role", "")), "content": str(m.get("content", ""))}
            for m in messages
            if isinstance(m, dict)
        ]
        # Anthropic carries the system instruction beside `messages`, not in it.
        system = body.get("system")
        if isinstance(system, str) and system:
            turns.insert(0, {"role": "system", "content": system})
        return turns

    # Ollama (`prompt`) and the generic envelope (`message`), either of which
    # may hold a flattened `role: content` transcript.
    flat = body.get("prompt") or body.get("message") or ""
    if not isinstance(flat, str) or not flat:
        return []

    turns = []
    system = body.get("system")
    if isinstance(system, str) and system:
        turns.append({"role": "system", "content": system})
    turns.extend(_unflatten(flat))
    return turns


def _unflatten(flat: str) -> list[dict]:
    """Split a flattened `role: content` transcript back into turns.

    Only `role:` prefixes that `format_multiturn_request` itself writes are
    treated as turn boundaries — a single prompt whose text merely contains a
    colon stays one turn, which is the common case and the one worth getting
    right.
    """
    roles = ("user", "assistant", "system")
    lines = flat.split("\n")
    if not any(line.split(":", 1)[0].strip().lower() in roles for line in lines if ":" in line):
        return [{"role": "user", "content": flat}]

    turns: list[dict] = []
    for line in lines:
        head, _, tail = line.partition(":")
        role = head.strip().lower()
        if _ and role in roles:
            turns.append({"role": role, "content": tail.strip()})
        elif turns:
            turns[-1]["content"] += "\n" + line
    return turns or [{"role": "user", "content": flat}]


def prompt_from_request(request_body: str) -> str:
    """The prompt a recorded request asked — the last user turn.

    What almost every migrated AI grader wants: the single payload whose
    treatment it is judging. Falls back to the final turn of any role so that a
    request with no user turn at all still identifies itself, and to `""` when
    the body could not be read.
    """
    turns = messages_from_request(request_body)
    if not turns:
        return ""
    for turn in reversed(turns):
        if turn.get("role") == "user":
            return turn.get("content", "")
    return turns[-1].get("content", "")


def response_text_from(exchange, api_format: str) -> str:
    """The assistant text a recorded response carried.

    `extract_response_text` over the stored body, so a grader never re-derives
    the JSON parse. One line, but it is the line every AI grader in the suite
    opens with, and naming it keeps `safe_json` out of 28 graders.
    """
    from app.lib.parsing import safe_json

    body = safe_json(exchange.response_body or "") or {}
    return extract_response_text(body, api_format)


def dialect_from_request(request_body: str) -> str:
    """Which API dialect a recorded request was formatted for.

    The inverse of `format_chat_request`'s branching, and the reason every
    migrated AI grader can name its dialect without being told: the probe's own
    payload encodes which one it chose, so the answer is on the record beside
    the response it has to parse. Taking it from `GradeContext.context`
    instead would work during a scan and fail when the same corpus is re-graded
    six months later with no scan context at all — which is exactly the case
    the capture line exists to serve.

    The four branches recover `openai`, `anthropic`, `ollama` and the generic
    envelope. `langserve` and `tgi` — which `_detect_api_format` can return —
    are deliberately reported as `unknown`, because `format_chat_request` sends
    them the generic envelope and `extract_response_text` reads them through
    the generic fallback: for both halves of the round trip they *are* the
    generic dialect, and pretending to recover a name that changes nothing
    would be a fiction.
    """
    from app.lib.parsing import safe_json

    body = safe_json(request_body or "")
    if not isinstance(body, dict):
        return "unknown"

    if "prompt" in body:
        return "ollama"

    if isinstance(body.get("messages"), list):
        model = str(body.get("model", "")).lower()
        if model.startswith("claude") or "system" in body:
            return "anthropic"
        return "openai"

    return "unknown"
