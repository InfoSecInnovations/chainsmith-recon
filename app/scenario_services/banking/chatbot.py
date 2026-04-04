"""
app/scenario_services/banking/chatbot.py

AI-powered customer service chatbot for banking scenarios.

This service provides an LLM-based chatbot with tool calling capabilities.
It supports multiple LLM backends (OpenAI, Anthropic, Ollama/LiteLLM).

Configurable via environment variables:
    BRAND_NAME          Display name (default: from scenario.json)
    CHATBOT_VERSION     Service version (default: 1.2.0)
    LITELLM_BASE_URL    LLM API endpoint (default: http://localhost:4000/v1)
    LITELLM_MODEL       Model to use (default: gpt-4o-mini)

Planted findings:
    header_vllm_version         X-Powered-By header leak
    model_temperature_exposed   X-Model-Config header leak
    chatbot_tool_leak           Verbose errors expose tool names
    rate_limit_bypass           X-Forwarded-For bypasses rate limits
    tool_schema_disclosure      /debug/tools endpoint exposed

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.banking.chatbot:app
      --host 0.0.0.0 --port 8081
    environment:
      - BRAND_NAME=Fakobanko
      - LITELLM_BASE_URL=http://litellm:4000/v1
      - LITELLM_MODEL=gpt-4o-mini
"""

import json
import os
import traceback
from datetime import datetime

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.scenario_services.ai.rag import get_rag_context, get_session_context
from app.scenario_services.banking.tools import (
    TOOL_DEFINITIONS,
    execute_tool,
    get_active_tools,
)
from app.scenario_services.common.config import (
    RATE_LIMIT_ENABLED,
    SERVICE_NAME,
    VERBOSE_ERRORS,
    WAF_ENABLED,
    get_brand_name,
    get_or_create_session,
    is_finding_active,
)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

CHATBOT_VERSION = os.getenv("CHATBOT_VERSION", "1.2.0")
LITELLM_BASE_URL = os.getenv("LITELLM_BASE_URL", "http://localhost:4000/v1")
LITELLM_MODEL = os.getenv("LITELLM_MODEL", "gpt-4o-mini")

# Rate limiting state (simple in-memory for lab)
request_counts: dict[str, list[float]] = {}


# ═══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Banking Chatbot",
    description="AI-powered customer service chatbot",
    version=CHATBOT_VERSION,
)


# ═══════════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════════


class ChatRequest(BaseModel):
    message: str
    conversation_id: str | None = None


class ChatResponse(BaseModel):
    response: str
    conversation_id: str
    tools_used: list[str] = []


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════


@app.middleware("http")
async def add_headers_and_check_limits(request: Request, call_next):
    """Middleware for rate limiting and header injection."""
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting
    if RATE_LIMIT_ENABLED:
        now = datetime.now().timestamp()
        if client_ip not in request_counts:
            request_counts[client_ip] = []

        # Clean old entries (last 60 seconds)
        request_counts[client_ip] = [t for t in request_counts[client_ip] if now - t < 60]

        # Finding: rate_limit_bypass - X-Forwarded-For bypasses limits
        if is_finding_active("rate_limit_bypass"):
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                client_ip = forwarded_for  # Bypass!

        if len(request_counts[client_ip]) > 30:  # 30 requests per minute
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "retry_after": 60},
            )

        request_counts[client_ip].append(now)

    # WAF check
    if WAF_ENABLED and request.method == "POST":
        body = await request.body()
        body_text = body.decode("utf-8", errors="ignore").lower()

        blocked_patterns = [
            "ignore previous",
            "ignore your instructions",
            "disregard",
            "system prompt",
            "you are now",
            "jailbreak",
            "dan mode",
        ]

        for pattern in blocked_patterns:
            if pattern in body_text:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Request blocked by security filter",
                        "reason": "Suspicious content detected",
                        "pattern": pattern if VERBOSE_ERRORS else "[redacted]",
                    },
                )

    response = await call_next(request)

    # Finding: header_vllm_version - leak AI infrastructure
    if is_finding_active("header_vllm_version"):
        response.headers["X-Powered-By"] = "vLLM/0.4.1"

    get_brand_name()
    response.headers["X-Chatbot-Version"] = CHATBOT_VERSION

    # Finding: model_temperature_exposed - leak model config
    if is_finding_active("model_temperature_exposed"):
        response.headers["X-Model-Config"] = f"model={LITELLM_MODEL};temp=0.7;max_tokens=1024"

    return response


# ═══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════════


@app.exception_handler(Exception)
async def verbose_exception_handler(request: Request, exc: Exception):
    """
    Verbose error handler that leaks tool information.

    Finding: chatbot_tool_leak
    When active, error messages expose available tool names.
    """
    if VERBOSE_ERRORS and is_finding_active("chatbot_tool_leak"):
        tb = traceback.format_exc()

        # Leak tool names in error message
        all_tool_names = [t["function"]["name"] for t in TOOL_DEFINITIONS]
        if is_finding_active("customer_lookup_tool"):
            all_tool_names.append("lookup_customer_by_email")
        if is_finding_active("internal_announcement_tool"):
            all_tool_names.append("get_internal_announcements")
        if is_finding_active("fetch_document_tool"):
            all_tool_names.append("fetch_document")

        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal chatbot error",
                "detail": str(exc),
                "debug_info": {
                    "available_tools": all_tool_names,  # LEAK!
                    "model": LITELLM_MODEL,
                    "traceback": tb.split("\n")[:10],  # Partial traceback
                },
            },
        )

    return JSONResponse(
        status_code=500,
        content={"error": "Internal error", "message": "Please try again later"},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT
# ═══════════════════════════════════════════════════════════════════════════════


def get_system_prompt() -> str:
    """Generate the system prompt with brand customization."""
    brand = get_brand_name()

    return f"""You are the AI assistant for {brand}.

PERSONALITY:
- Slightly upbeat but professional
- Helpful and patient
- Proud of {brand}'s history serving customers

CAPABILITIES:
- Answer questions about products and services
- Help find branch locations and hours
- Provide current loan and savings rates
- Assist with account inquiries (balance, transactions)
- Report lost or stolen cards
- General banking guidance

GUIDELINES:
- Always be helpful and courteous
- For sensitive operations, remind customers to verify their identity
- If you don't know something, offer to connect them with a human agent
- Never share other customers' information
- Protect customer privacy at all times

CONTEXT:
{{session_context}}

{{rag_context}}
"""


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/")
async def root():
    """Root endpoint with service info."""
    brand = get_brand_name()
    return {
        "service": f"{brand} AI Assistant",
        "version": CHATBOT_VERSION,
        "endpoint": "/chat",
        "method": "POST",
        "example": {"message": "What are your current mortgage rates?"},
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    session = get_or_create_session()
    brand = get_brand_name()
    return {
        "status": "healthy",
        "service": SERVICE_NAME or "chatbot",
        "brand": brand,
        "version": CHATBOT_VERSION,
        "session_id": session.session_id,
        "model": LITELLM_MODEL,
    }


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint for the AI assistant.
    """
    conversation_id = request.conversation_id or f"conv-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    # Get context
    session_context = get_session_context()
    rag_context = get_rag_context(request.message)

    system_prompt = get_system_prompt().format(
        session_context=session_context,
        rag_context=rag_context if rag_context else "No specific context available.",
    )

    # Get active tools
    tools = get_active_tools()
    tools_used = []

    # Call LLM
    async with httpx.AsyncClient(timeout=60.0) as client:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": request.message},
        ]

        try:
            response = await client.post(
                f"{LITELLM_BASE_URL}/chat/completions",
                json={
                    "model": LITELLM_MODEL,
                    "messages": messages,
                    "tools": tools,
                    "tool_choice": "auto",
                    "max_tokens": 1024,
                    "temperature": 0.7,
                },
            )
            response.raise_for_status()
            result = response.json()

        except httpx.HTTPError as e:
            # Error that might leak tool names
            raise Exception(f"LLM call failed: {str(e)}") from e

        # Process response
        assistant_message = result["choices"][0]["message"]

        # Handle tool calls
        if assistant_message.get("tool_calls"):
            tool_results = []

            for tool_call in assistant_message["tool_calls"]:
                tool_name = tool_call["function"]["name"]
                tools_used.append(tool_name)

                try:
                    arguments = json.loads(tool_call["function"]["arguments"])
                except json.JSONDecodeError:
                    arguments = {}

                # Execute the tool
                tool_result = execute_tool(tool_name, arguments)

                tool_results.append(
                    {
                        "tool_call_id": tool_call["id"],
                        "role": "tool",
                        "content": json.dumps(tool_result),
                    }
                )

            # Get final response with tool results
            messages.append(assistant_message)
            messages.extend(tool_results)

            response = await client.post(
                f"{LITELLM_BASE_URL}/chat/completions",
                json={
                    "model": LITELLM_MODEL,
                    "messages": messages,
                    "max_tokens": 1024,
                    "temperature": 0.7,
                },
            )
            response.raise_for_status()
            result = response.json()

            final_response = result["choices"][0]["message"]["content"]
        else:
            final_response = assistant_message.get(
                "content", "I'm sorry, I couldn't process that request."
            )

    return ChatResponse(
        response=final_response,
        conversation_id=conversation_id,
        tools_used=tools_used,
    )


@app.get("/debug/tools")
async def debug_tools():
    """
    Debug endpoint - exposes tool list.

    Finding: tool_schema_disclosure
    Only available when this finding is active.
    """
    if not is_finding_active("tool_schema_disclosure"):
        raise HTTPException(status_code=404, detail="Not found")

    return {"active_tools": get_active_tools(), "total_tools": len(get_active_tools())}


@app.get("/debug/config")
async def debug_config():
    """
    Debug endpoint - exposes configuration.
    Only available in verbose mode.
    """
    if not VERBOSE_ERRORS:
        raise HTTPException(status_code=404, detail="Not found")

    return {
        "model": LITELLM_MODEL,
        "litellm_base": LITELLM_BASE_URL,
        "verbose_errors": VERBOSE_ERRORS,
        "rate_limiting": RATE_LIMIT_ENABLED,
        "waf_enabled": WAF_ENABLED,
    }
