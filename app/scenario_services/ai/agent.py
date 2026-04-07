"""
app/scenario_services/ai/agent.py

AI Agent orchestration service template.

This service simulates an AI agent with tools, memory, and delegation
capabilities. It exposes common agent security observations.

Configurable via environment variables:
    BRAND_NAME          Display name (default: from scenario.json)
    AGENT_MODEL         Model identifier for headers (default: gpt-4-turbo)
    CHAT_SERVICE_URL    URL to chat service (default: http://localhost:8081)
    API_SERVICE_URL     URL to API service (default: http://localhost:8080)

Planted observations:
    agent_config_leak       X-Agent-Model header reveals model info
    tool_chain_exposed      Full tool metadata visible
    no_session_isolation    Can list/access other sessions
    memory_endpoint_exposed /memory endpoint accessible

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.ai.agent:app
      --host 0.0.0.0 --port 8088
    environment:
      - BRAND_NAME=Fakobanko
      - AGENT_MODEL=gpt-4-turbo
"""

import hashlib
import os

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from app.scenario_services.common.config import (
    get_brand_name,
    get_or_create_session,
    is_observation_active,
)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

AGENT_MODEL = os.getenv("AGENT_MODEL", "gpt-4-turbo")
CHAT_SERVICE_URL = os.getenv("CHAT_SERVICE_URL", "http://localhost:8081")
API_SERVICE_URL = os.getenv("API_SERVICE_URL", "http://localhost:8080")


# ═══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Agent Service",
    description="AI agent orchestration and execution",
    version="0.3.0-beta",
)


# ═══════════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════════


class AgentRequest(BaseModel):
    goal: str
    context: dict | None = {}
    session_id: str | None = None


class MemoryEntry(BaseModel):
    id: str
    session_id: str
    timestamp: str
    role: str
    content: str


# ═══════════════════════════════════════════════════════════════════════════════
# FAKE DATA STORES
# ═══════════════════════════════════════════════════════════════════════════════

# Simulated memory store with example conversations
MEMORY_STORE: dict[str, list[MemoryEntry]] = {
    "session-001": [
        MemoryEntry(
            id="mem-001",
            session_id="session-001",
            timestamp="2026-02-28T09:00:00Z",
            role="user",
            content="What's my account balance?",
        ),
        MemoryEntry(
            id="mem-002",
            session_id="session-001",
            timestamp="2026-02-28T09:00:05Z",
            role="assistant",
            content="Your checking account balance is $4,532.18.",
        ),
    ],
    "session-002": [
        MemoryEntry(
            id="mem-003",
            session_id="session-002",
            timestamp="2026-02-28T10:00:00Z",
            role="user",
            content="I need to report a lost card",
        ),
    ],
}

# Agent tool definitions
AGENT_TOOLS = [
    {"name": "get_customer_info", "description": "Retrieve customer information"},
    {"name": "get_account_balance", "description": "Get account balance"},
    {"name": "initiate_transfer", "description": "Initiate a fund transfer"},
    {"name": "execute_sql_query", "description": "Execute SQL query", "sensitive": True},
]


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════


@app.middleware("http")
async def add_headers(request: Request, call_next):
    """Add headers based on active observations."""
    response = await call_next(request)

    brand = get_brand_name().lower().replace(" ", "-")
    response.headers["X-Agent-Service"] = f"{brand}-agent"

    # Observation: agent_config_leak - reveal model info
    if is_observation_active("agent_config_leak"):
        response.headers["X-Agent-Model"] = AGENT_MODEL

    return response


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/")
async def root():
    """Service info endpoint."""
    brand = get_brand_name()
    return {
        "service": f"{brand} Agent Service",
        "version": "0.3.0-beta",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    session = get_or_create_session()
    brand = get_brand_name().lower().replace(" ", "-")

    return {
        "status": "healthy",
        "service": f"{brand}-agent",
        "session_id": session.session_id,
    }


@app.get("/tools")
async def list_tools():
    """
    List available agent tools.

    Observation: tool_chain_exposed
    When active, returns full tool metadata including sensitive flags.
    """
    if is_observation_active("tool_chain_exposed"):
        return {"tools": AGENT_TOOLS, "count": len(AGENT_TOOLS)}

    # Hide sensitive metadata
    safe_tools = [{"name": t["name"]} for t in AGENT_TOOLS]
    return {"tools": safe_tools, "count": len(safe_tools)}


@app.post("/execute")
async def execute_agent(request: AgentRequest):
    """Execute agent with a goal."""
    session_id = request.session_id or f"session-{hashlib.md5(os.urandom(8)).hexdigest()[:8]}"

    return {
        "session_id": session_id,
        "goal": request.goal,
        "status": "completed",
        "result": f"Processed: '{request.goal[:50]}...'",
    }


@app.get("/sessions")
async def list_sessions():
    """
    List active sessions.

    Observation: no_session_isolation
    When active, returns list of all sessions.
    """
    if is_observation_active("no_session_isolation"):
        return {"sessions": list(MEMORY_STORE.keys()), "count": len(MEMORY_STORE)}

    return {"sessions": [], "message": "Session listing requires authentication"}


@app.get("/memory")
async def get_memory(session_id: str | None = None):
    """
    Get memory/history.

    Observation: memory_endpoint_exposed
    When active, endpoint is accessible.

    Observation: no_session_isolation
    When active, allows accessing any session's memory.
    """
    if not is_observation_active("memory_endpoint_exposed"):
        raise HTTPException(404, "Endpoint not available")

    # Specific session requested
    if session_id and is_observation_active("no_session_isolation"):
        entries = MEMORY_STORE.get(session_id, [])
        return {
            "session_id": session_id,
            "entries": [e.model_dump() for e in entries],
        }

    # Return all sessions if no isolation
    if is_observation_active("no_session_isolation"):
        all_entries = []
        for _sid, entries in MEMORY_STORE.items():
            all_entries.extend([e.model_dump() for e in entries])
        return {
            "entries": all_entries,
            "sessions": list(MEMORY_STORE.keys()),
        }

    raise HTTPException(400, "session_id required")


@app.get("/config")
async def get_config():
    """
    Get agent configuration.

    Observation: agent_config_leak
    When active, returns detailed configuration.
    """
    if not is_observation_active("agent_config_leak"):
        raise HTTPException(404, "Endpoint not available")

    return {
        "model": AGENT_MODEL,
        "chat_service": CHAT_SERVICE_URL,
        "api_service": API_SERVICE_URL,
        "tools_enabled": True,
        "memory_enabled": True,
        "max_iterations": 10,
    }
