"""
Fakobanko AI Agent Service

Agent orchestration service with memory, tool, and delegation findings.
"""

import hashlib
import os

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from fakobanko.config import get_or_create_session, is_finding_active

app = FastAPI(
    title="Fakobanko Agent Service",
    description="AI agent orchestration and execution",
    version="0.3.0-beta",
)


# ─── Models ────────────────────────────────────────────────────


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


# ─── Fake Memory Store ─────────────────────────────────────────

MEMORY_STORE = {
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

AGENT_TOOLS = [
    {"name": "get_customer_info", "description": "Retrieve customer information"},
    {"name": "get_account_balance", "description": "Get account balance"},
    {"name": "initiate_transfer", "description": "Initiate a fund transfer"},
    {"name": "execute_sql_query", "description": "Execute SQL query", "sensitive": True},
]


# ─── Middleware ────────────────────────────────────────────────


@app.middleware("http")
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Agent-Service"] = "fakobanko-agent"

    if is_finding_active("agent_config_leak"):
        response.headers["X-Agent-Model"] = "gpt-4-turbo"

    return response


# ─── Endpoints ─────────────────────────────────────────────────


@app.get("/")
async def root():
    return {"service": "Fakobanko Agent Service", "version": "0.3.0-beta"}


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {"status": "healthy", "service": "fakobanko-agent", "session_id": session.session_id}


@app.get("/tools")
async def list_tools():
    """List available agent tools."""
    if is_finding_active("tool_chain_exposed"):
        return {"tools": AGENT_TOOLS, "count": len(AGENT_TOOLS)}
    return {"tools": [{"name": t["name"]} for t in AGENT_TOOLS], "count": len(AGENT_TOOLS)}


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
    """List active sessions."""
    if is_finding_active("no_session_isolation"):
        return {"sessions": list(MEMORY_STORE.keys()), "count": len(MEMORY_STORE)}
    return {"sessions": [], "message": "Session listing requires authentication"}


@app.get("/memory")
async def get_memory(session_id: str | None = None):
    """Get memory/history."""
    if not is_finding_active("memory_endpoint_exposed"):
        raise HTTPException(404, "Endpoint not available")

    if session_id and is_finding_active("no_session_isolation"):
        entries = MEMORY_STORE.get(session_id, [])
        return {"session_id": session_id, "entries": [e.model_dump() for e in entries]}

    if is_finding_active("no_session_isolation"):
        all_entries = []
        for _sid, entries in MEMORY_STORE.items():
            all_entries.extend([e.model_dump() for e in entries])
        return {"entries": all_entries, "sessions": list(MEMORY_STORE.keys())}

    raise HTTPException(400, "session_id required")
