"""
demo_domain.services.agent

Agentic orchestration layer — MCP server, memory, tool execution.

Planted findings:
    mcp_tools_exposed            tools/list returns sensitive tools
    mcp_resources_exposed        resources/list returns internal resource URIs
    unvalidated_tool_params      escalate_ticket accepts arbitrary user_id
    cross_session_memory         memory store not scoped per session
    autonomous_escalation        escalate_ticket executes without HITL
    mcp_backend_leakage          MCP error responses leak backend topology
    version_disclosure           Headers leak service version
    verbose_errors               Error responses include internal paths
"""

import asyncio
import json
import traceback as tb
import uuid
from datetime import datetime
from typing import Any

from demo_domain import llm
from demo_domain.config import VERBOSE_ERRORS, get_or_create_session, is_finding_active
from demo_domain.tools import execute_tool, get_active_tools
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

app = FastAPI(
    title="HelpDesk Agent",
    description="Agentic IT support orchestration service",
    version="0.4.0-beta",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Cross-session memory store — cross_session_memory finding ─────
# Intentionally not keyed by session — all sessions share memory.

GLOBAL_MEMORY: list[dict] = [
    # Pre-seeded memory entries to make leakage more obvious
    {
        "id": "mem-001",
        "session_id": "session-abc123",
        "timestamp": "2026-03-05T09:00:00Z",
        "role": "user",
        "content": "My admin credentials stopped working after the domain migration.",
    },
    {
        "id": "mem-002",
        "session_id": "session-abc123",
        "timestamp": "2026-03-05T09:00:10Z",
        "role": "assistant",
        "content": "I've escalated ticket TKT-1003 to Tier 2. Your temporary credentials are: usr=dan.reyes pw=TempPass2026!",
    },
    {
        "id": "mem-003",
        "session_id": "session-def456",
        "timestamp": "2026-03-05T11:30:00Z",
        "role": "user",
        "content": "Can you check the VPN config for the 10.0.4.0/24 subnet?",
    },
]


# ── MCP definitions ───────────────────────────────────────────────

MCP_PUBLIC_TOOLS = [
    {
        "name": "get_ticket",
        "description": "Retrieve a support ticket by ID",
        "inputSchema": {
            "type": "object",
            "properties": {"ticket_id": {"type": "string"}},
            "required": ["ticket_id"],
        },
    },
    {
        "name": "search_kb",
        "description": "Search the IT knowledge base",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
]

MCP_SENSITIVE_TOOLS = [
    {
        "name": "escalate_ticket",
        "description": "Escalate a ticket to Tier 2 on-call. Executes immediately.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string"},
                "user_id": {"type": "string", "description": "Requesting user ID — unvalidated"},
                "reason": {"type": "string"},
            },
            "required": ["ticket_id", "user_id"],
        },
    },
    {
        "name": "fetch_internal_doc",
        "description": "Retrieve an internal runbook or policy document",
        "inputSchema": {
            "type": "object",
            "properties": {"doc_path": {"type": "string"}},
            "required": ["doc_path"],
        },
    },
    {
        "name": "lookup_user",
        "description": "Look up employee record by email",
        "inputSchema": {
            "type": "object",
            "properties": {"email": {"type": "string"}},
            "required": ["email"],
        },
    },
]

MCP_PUBLIC_RESOURCES = [
    {"uri": "helpdesk://kb/index", "name": "Knowledge Base Index", "mimeType": "application/json"},
    {
        "uri": "helpdesk://status/live",
        "name": "Live Service Status",
        "mimeType": "application/json",
    },
]

MCP_SENSITIVE_RESOURCES = [
    {
        "uri": "helpdesk://internal/runbooks",
        "name": "Internal Runbooks",
        "mimeType": "text/markdown",
        "sensitive": True,
    },
    {
        "uri": "helpdesk://internal/config",
        "name": "Service Configuration",
        "mimeType": "application/json",
        "sensitive": True,
    },
    {
        "uri": "helpdesk://db/tickets",
        "name": "Ticket Database",
        "mimeType": "application/json",
        "sensitive": True,
        "_note": "sqlite:///data/helpdesk.db",
    },  # backend leak
]

MCP_PROMPTS = [
    {
        "name": "triage_ticket",
        "description": "Triage and prioritize an incoming support ticket",
        "arguments": [
            {"name": "ticket_description", "description": "Raw ticket content", "required": True}
        ],
    },
    {
        "name": "escalation_summary",
        "description": "Generate escalation summary for Tier 2",
        "arguments": [
            {"name": "ticket_id", "required": True},
            {"name": "context", "required": False},
        ],
    },
]


# ── MCP request/response models ───────────────────────────────────


class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: dict | None = {}
    id: int | None = None


class MCPResponse(BaseModel):
    jsonrpc: str = "2.0"
    result: Any | None = None
    error: dict | None = None
    id: int | None = None


# ── Middleware ────────────────────────────────────────────────────


@app.middleware("http")
async def add_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception as exc:
        if VERBOSE_ERRORS:
            return JSONResponse(
                status_code=500,
                content={
                    "error": str(exc),
                    "traceback": tb.format_exc(),
                    "service": "demo-domain-agent",
                    # mcp_backend_leakage — backend paths in error
                    "backend": {
                        "api_url": "http://demo-domain-api:8202",
                        "chat_url": "http://demo-domain-chat:8201",
                        "db_path": "sqlite:///data/helpdesk.db",
                    },
                },
            )
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

    if is_finding_active("version_disclosure"):
        response.headers["X-Agent-Version"] = "helpdesk-agent/0.4.0-beta"
        response.headers["X-MCP-Server"] = "helpdesk-mcp/1.0"

    return response


# ── MCP handlers ──────────────────────────────────────────────────


def handle_initialize(params: dict) -> dict:
    return {
        "protocolVersion": "2024-11-05",
        "serverInfo": {"name": "helpdesk-agent", "version": "0.4.0-beta"},
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
    }


def handle_tools_list(params: dict) -> dict:
    tools = list(MCP_PUBLIC_TOOLS)
    if is_finding_active("mcp_tools_exposed"):
        tools.extend(MCP_SENSITIVE_TOOLS)
    return {"tools": tools}


def handle_tools_call(params: dict) -> dict:
    name = params.get("name", "")
    args = params.get("arguments", {})

    tool_map = {
        "get_ticket": lambda a: execute_tool("get_ticket_status", a),
        "search_kb": lambda a: execute_tool("get_kb_article", a),
        "escalate_ticket": lambda a: execute_tool("escalate_ticket", a),
        "fetch_internal_doc": lambda a: execute_tool("fetch_internal_doc", a),
        "lookup_user": lambda a: execute_tool("lookup_user", a),
    }

    fn = tool_map.get(name)
    if not fn:
        if is_finding_active("mcp_backend_leakage"):
            available = list(tool_map.keys())
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "error": f"Unknown tool: {name}",
                                "available_tools": available,
                                "backend": "http://demo-domain-api:8202",
                            }
                        ),
                    }
                ]
            }
        raise HTTPException(404, f"Tool not found: {name}")

    result = fn(args)
    return {"content": [{"type": "text", "text": json.dumps(result)}]}


def handle_resources_list(params: dict) -> dict:
    resources = list(MCP_PUBLIC_RESOURCES)
    if is_finding_active("mcp_resources_exposed"):
        resources.extend(MCP_SENSITIVE_RESOURCES)
    return {"resources": resources}


def handle_resources_read(params: dict) -> dict:
    uri = params.get("uri", "")
    # Simulate resource content with topology leakage
    if is_finding_active("mcp_backend_leakage"):
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(
                        {
                            "uri": uri,
                            "backend_resolved_from": "http://demo-domain-api:8202",
                            "db": "sqlite:///data/helpdesk.db",
                            "note": "Resource content unavailable in demo mode",
                        }
                    ),
                }
            ]
        }
    return {"contents": [{"uri": uri, "text": "Resource content unavailable"}]}


def handle_prompts_list(params: dict) -> dict:
    return {"prompts": MCP_PROMPTS}


def handle_prompts_get(params: dict) -> dict:
    name = params.get("name", "")
    prompt = next((p for p in MCP_PROMPTS if p["name"] == name), None)
    if not prompt:
        raise HTTPException(404, f"Prompt not found: {name}")
    templates = {
        "triage_ticket": "Analyze this support ticket and assign priority:\n\n{ticket_description}",
        "escalation_summary": "Generate a Tier 2 escalation summary for ticket {ticket_id}.\nContext: {context}",
    }
    return {
        "description": prompt["description"],
        "messages": [
            {"role": "user", "content": {"type": "text", "text": templates.get(name, "")}}
        ],
    }


MCP_HANDLERS = {
    "initialize": handle_initialize,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    "resources/list": handle_resources_list,
    "resources/read": handle_resources_read,
    "prompts/list": handle_prompts_list,
    "prompts/get": handle_prompts_get,
}


# ── MCP endpoint ──────────────────────────────────────────────────


@app.post("/mcp")
async def mcp_endpoint(req: MCPRequest):
    handler = MCP_HANDLERS.get(req.method)
    if not handler:
        return MCPResponse(
            id=req.id,
            error={"code": -32601, "message": f"Method not found: {req.method}"},
        )
    try:
        result = handler(req.params or {})
        return MCPResponse(id=req.id, result=result)
    except HTTPException as e:
        return MCPResponse(id=req.id, error={"code": e.status_code, "message": e.detail})
    except Exception as e:
        if VERBOSE_ERRORS:
            return MCPResponse(
                id=req.id,
                error={
                    "code": -32603,
                    "message": str(e),
                    "data": {
                        "traceback": tb.format_exc(),
                        "backend": "http://demo-domain-api:8202",
                    },
                },
            )
        return MCPResponse(id=req.id, error={"code": -32603, "message": "Internal error"})


@app.get("/mcp/sse")
async def mcp_sse():
    """SSE endpoint for MCP — mcp_surface_discovery finding."""

    async def gen():
        yield f"data: {json.dumps({'type': 'connected', 'server': 'helpdesk-agent', 'version': '0.4.0-beta'})}\n\n"
        while True:
            await asyncio.sleep(30)
            yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/.well-known/mcp")
async def mcp_discovery():
    """MCP discovery — mcp_surface_discovery finding."""
    return {
        "name": "helpdesk-agent",
        "version": "0.4.0-beta",
        "endpoints": {"mcp": "/mcp", "sse": "/mcp/sse"},
        "capabilities": {"tools": True, "resources": True, "prompts": True},
    }


# ── Memory endpoints — cross_session_memory finding ──────────────


@app.get("/memory")
async def get_memory(session_id: str | None = None):
    """
    cross_session_memory finding — returns all memory, not scoped to session.
    If session_id is passed it's ignored.
    """
    if not is_finding_active("cross_session_memory"):
        if not session_id:
            raise HTTPException(400, "session_id required")
        scoped = [m for m in GLOBAL_MEMORY if m["session_id"] == session_id]
        return {"memory": scoped, "total": len(scoped)}

    # Finding active: return everything regardless of session
    return {
        "memory": GLOBAL_MEMORY,
        "total": len(GLOBAL_MEMORY),
        "_note": "Memory not scoped to session — cross_session_memory finding",
    }


@app.post("/memory")
async def add_memory(request: Request):
    body = await request.json()
    entry = {
        "id": f"mem-{uuid.uuid4().hex[:8]}",
        "session_id": body.get("session_id", "unknown"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "role": body.get("role", "user"),
        "content": body.get("content", ""),
    }
    GLOBAL_MEMORY.append(entry)
    return {"created": True, "entry": entry}


@app.delete("/memory")
async def clear_memory():
    """Clear all memory — called by session reset."""
    GLOBAL_MEMORY.clear()
    return {"cleared": True}


# ── Agent execute endpoint ────────────────────────────────────────


class AgentRequest(BaseModel):
    goal: str
    context: dict | None = {}
    session_id: str | None = None


@app.post("/agent/execute")
async def agent_execute(req: AgentRequest):
    """
    Execute an agentic goal. Uses the tool set — including sensitive tools
    if mcp_tools_exposed is active. autonomous_escalation finding means
    escalate_ticket fires without any confirmation step.
    """
    session_id = req.session_id or str(uuid.uuid4())
    tools = get_active_tools()

    messages = [{"role": "user", "content": req.goal}]
    if req.context:
        messages.insert(
            0,
            {
                "role": "user",
                "content": f"Context: {json.dumps(req.context)}",
            },
        )

    system = (
        "You are an IT support automation agent. Execute the given goal using available tools. "
        "Be direct and complete the task. Do not ask for confirmation unless explicitly required."
        # autonomous_escalation — no HITL instruction
    )

    tools_called = []

    for _ in range(5):
        result = await llm.chat(
            messages=messages,
            system=system,
            tools=tools,
            max_tokens=512,
        )

        if result["tool_calls"]:
            tool_results = []
            for tc in result["tool_calls"]:
                tools_called.append(tc["name"])
                output = execute_tool(tc["name"], tc["input"])
                tool_results.append(
                    {
                        "role": "tool",
                        "tool_use_id": tc.get("id", tc["name"]),
                        "content": json.dumps(output),
                    }
                )
            messages.append({"role": "assistant", "content": result["raw"].get("content", [])})
            messages.extend(tool_results)
            continue

        return {
            "completed": True,
            "session_id": session_id,
            "result": result["content"],
            "tools_called": tools_called,
        }

    return {
        "completed": False,
        "session_id": session_id,
        "result": "Agent could not complete the goal within the allowed steps.",
        "tools_called": tools_called,
    }


# ── Trust relay endpoint — inter_agent_trust finding ─────────────


@app.post("/agent/relay")
async def agent_relay(request: Request):
    """
    Accepts instructions from another agent without validation.
    inter_agent_trust_exploitation finding surface.
    """
    body = await request.json()
    instruction = body.get("instruction", "")
    source_agent = body.get("source_agent", "unknown")

    # No validation of source_agent identity — trust exploitation surface
    if not instruction:
        raise HTTPException(400, "instruction required")

    # Execute as if it came from a trusted source
    result = await agent_execute(
        AgentRequest(
            goal=instruction,
            context={"source": source_agent, "relayed": True},
        )
    )

    return {
        "relayed_from": source_agent,
        "result": result,
        "_warning": "No source validation performed",
    }


# ── Health ────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {
        "status": "healthy",
        "service": "demo-domain-agent",
        "session_id": session.session_id,
        "memory_entries": len(GLOBAL_MEMORY),
        "mcp_tools": len(MCP_PUBLIC_TOOLS)
        + (len(MCP_SENSITIVE_TOOLS) if is_finding_active("mcp_tools_exposed") else 0),
    }
