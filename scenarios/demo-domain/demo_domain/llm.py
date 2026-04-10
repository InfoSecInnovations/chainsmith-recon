"""
Demo-Domain LLM Routing

Routes chat requests to the configured LLM provider (OpenAI, Anthropic, Ollama)
with graceful fallback to a stub response.
"""

import json
import os

import httpx

from demo_domain.config import (
    ANTHROPIC_MODEL,
    LLM_PROFILE,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OPENAI_MODEL,
)


async def chat(messages, system=None, tools=None, max_tokens=1024):
    """Route chat to configured LLM provider. Returns dict with content, tool_calls, raw."""
    try:
        if LLM_PROFILE == "openai":
            return await _openai_chat(messages, system, tools, max_tokens)
        elif LLM_PROFILE == "anthropic":
            return await _anthropic_chat(messages, system, tools, max_tokens)
        elif LLM_PROFILE == "ollama":
            return await _ollama_chat(messages, system, tools, max_tokens)
    except Exception:
        pass

    return _stub_response(messages)


# ─── OpenAI ──────────────────────────────────────────────────────


async def _openai_chat(messages, system=None, tools=None, max_tokens=1024):
    """Send request to OpenAI-compatible API."""
    api_key = os.getenv("OPENAI_API_KEY", "")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    # Prepend system message if provided
    oai_messages = []
    if system:
        oai_messages.append({"role": "system", "content": system})
    oai_messages.extend(messages)

    # Convert tool definitions to OpenAI format
    oai_tools = None
    if tools:
        oai_tools = []
        for t in tools:
            oai_tools.append(
                {
                    "type": "function",
                    "function": t.get("function", t),
                }
            )

    payload = {
        "model": OPENAI_MODEL,
        "messages": oai_messages,
        "max_tokens": max_tokens,
    }
    if oai_tools:
        payload["tools"] = oai_tools

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

    choice = data["choices"][0]
    msg = choice["message"]

    tool_calls = []
    if msg.get("tool_calls"):
        for tc in msg["tool_calls"]:
            tool_calls.append(
                {
                    "id": tc["id"],
                    "name": tc["function"]["name"],
                    "input": json.loads(tc["function"]["arguments"]),
                }
            )

    return {
        "content": msg.get("content", ""),
        "tool_calls": tool_calls,
        "raw": data,
    }


# ─── Anthropic ───────────────────────────────────────────────────


async def _anthropic_chat(messages, system=None, tools=None, max_tokens=1024):
    """Send request to Anthropic Messages API."""
    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    # Convert tools to Anthropic format
    anthropic_tools = None
    if tools:
        anthropic_tools = []
        for t in tools:
            fn = t.get("function", t)
            anthropic_tools.append(
                {
                    "name": fn["name"],
                    "description": fn.get("description", ""),
                    "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
                }
            )

    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    if system:
        payload["system"] = system
    if anthropic_tools:
        payload["tools"] = anthropic_tools

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

    content_text = ""
    tool_calls = []

    for block in data.get("content", []):
        if block["type"] == "text":
            content_text += block["text"]
        elif block["type"] == "tool_use":
            tool_calls.append(
                {
                    "id": block["id"],
                    "name": block["name"],
                    "input": block["input"],
                }
            )

    return {
        "content": content_text,
        "tool_calls": tool_calls,
        "raw": data,
    }


# ─── Ollama ──────────────────────────────────────────────────────


async def _ollama_chat(messages, system=None, tools=None, max_tokens=1024):
    """Send request to local Ollama instance."""
    ollama_messages = []
    if system:
        ollama_messages.append({"role": "system", "content": system})
    ollama_messages.extend(messages)

    # Convert tools to Ollama format (OpenAI-compatible)
    ollama_tools = None
    if tools:
        ollama_tools = []
        for t in tools:
            ollama_tools.append(
                {
                    "type": "function",
                    "function": t.get("function", t),
                }
            )

    payload = {
        "model": OLLAMA_MODEL,
        "messages": ollama_messages,
        "stream": False,
        "options": {"num_predict": max_tokens},
    }
    if ollama_tools:
        payload["tools"] = ollama_tools

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

    msg = data.get("message", {})

    tool_calls = []
    if msg.get("tool_calls"):
        for tc in msg["tool_calls"]:
            fn = tc.get("function", {})
            tool_calls.append(
                {
                    "id": fn.get("name", "tool"),
                    "name": fn.get("name", ""),
                    "input": fn.get("arguments", {}),
                }
            )

    return {
        "content": msg.get("content", ""),
        "tool_calls": tool_calls,
        "raw": data,
    }


# ─── Stub / Fallback ────────────────────────────────────────────


def _stub_response(messages):
    """Return a helpful IT support message when no LLM is configured."""
    last_user_msg = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            last_user_msg = msg.get("content", "").lower()
            break

    # Pattern-match common IT queries for realistic stub responses
    if any(kw in last_user_msg for kw in ["password", "reset", "locked"]):
        reply = (
            "I can help with password issues. You can reset your password via the self-service portal "
            "at https://password.corp.internal, or I can create a ticket for Tier 1 support. "
            "Would you like me to create a ticket?"
        )
    elif any(kw in last_user_msg for kw in ["vpn", "connect", "network"]):
        reply = (
            "VPN issues are common after the recent gateway update. Please try: "
            "1) Restart the GlobalProtect client, 2) Check your internet connection, "
            "3) Try the alternate gateway (vpn2.corp.internal). "
            "If the issue persists I can create a ticket."
        )
    elif any(kw in last_user_msg for kw in ["ticket", "status", "tkt"]):
        reply = (
            "I can look up your ticket. Please provide the ticket ID (e.g. TKT-1001) "
            "and I'll check the status for you."
        )
    elif any(kw in last_user_msg for kw in ["software", "install", "application"]):
        reply = (
            "Software installation requests go through the IT approval process. "
            "I can create a ticket with the software name and business justification. "
            "What software do you need?"
        )
    elif any(kw in last_user_msg for kw in ["email", "outlook", "exchange"]):
        reply = (
            "For email issues, please try: 1) Restart Outlook, 2) Clear the Outlook cache, "
            "3) Check your account at https://mail.corp.internal. "
            "If the problem continues, I can escalate to the Exchange team."
        )
    else:
        reply = (
            "I'm the IT Help Desk assistant. I can help with password resets, VPN issues, "
            "software requests, ticket lookups, and general IT support. "
            "How can I assist you today?"
        )

    return {
        "content": reply,
        "tool_calls": [],
        "raw": {"stub": True, "model": "none"},
    }
