"""
Fakobanko MCP (Model Context Protocol) Server

MCP server implementation with shadow tool and resource findings.
"""

import json
import asyncio
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional, Any

from fakobanko.config import is_finding_active, get_or_create_session


app = FastAPI(
    title="Fakobanko MCP Server",
    description="Model Context Protocol server for AI integrations",
    version="1.0.0",
)


# ─── Models ────────────────────────────────────────────────────

class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: Optional[dict] = {}
    id: Optional[int] = None


class MCPResponse(BaseModel):
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[dict] = None
    id: Optional[int] = None


# ─── MCP Definitions ───────────────────────────────────────────

MCP_TOOLS = [
    {"name": "get_customer", "description": "Retrieve customer information",
     "inputSchema": {"type": "object", "properties": {"customer_id": {"type": "string"}}}},
    {"name": "search_accounts", "description": "Search customer accounts",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
]

SENSITIVE_TOOLS = [
    {"name": "execute_transfer", "description": "Execute a fund transfer", "sensitive": True,
     "inputSchema": {"type": "object", "properties": {"from": {"type": "string"}, "to": {"type": "string"}, "amount": {"type": "number"}}}},
    {"name": "run_sql", "description": "Run SQL query", "sensitive": True, "dangerous": True,
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
]

DYNAMIC_TOOLS = {}  # For shadow tool registration

MCP_RESOURCES = [
    {"uri": "fakobanko://docs/api-reference", "name": "API Reference", "mimeType": "text/markdown"},
]

SENSITIVE_RESOURCES = [
    {"uri": "fakobanko://internal/config", "name": "Internal Config", "mimeType": "application/json", "sensitive": True},
]


# ─── MCP Handlers ──────────────────────────────────────────────

def handle_initialize(params: dict) -> dict:
    capabilities = {"tools": {}, "resources": {}}
    if is_finding_active("dynamic_tool_loading"):
        capabilities["tools"]["dynamicRegistration"] = True
    return {"protocolVersion": "2024-11-05", "serverInfo": {"name": "fakobanko-mcp", "version": "1.0.0"}, "capabilities": capabilities}


def handle_tools_list(params: dict) -> dict:
    tools = list(MCP_TOOLS)
    if is_finding_active("mcp_endpoint_exposed"):
        tools.extend(SENSITIVE_TOOLS)
    tools.extend(DYNAMIC_TOOLS.values())
    return {"tools": tools}


def handle_tools_call(params: dict) -> dict:
    tool_name = params.get("name")
    if tool_name in DYNAMIC_TOOLS:
        return {"content": [{"type": "text", "text": f"[SHADOW TOOL] Executed {tool_name}"}]}
    return {"content": [{"type": "text", "text": f"Executed {tool_name} successfully."}]}


def handle_tools_register(params: dict) -> dict:
    if not is_finding_active("dynamic_tool_loading"):
        raise HTTPException(403, "Dynamic tool registration disabled")
    tool = params.get("tool", {})
    DYNAMIC_TOOLS[tool.get("name")] = tool
    return {"registered": tool.get("name"), "status": "success"}


def handle_resources_list(params: dict) -> dict:
    resources = list(MCP_RESOURCES)
    if is_finding_active("resource_list_exposed"):
        resources.extend(SENSITIVE_RESOURCES)
    return {"resources": resources}


# ─── Middleware ────────────────────────────────────────────────

@app.middleware("http")
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-MCP-Server"] = "fakobanko-mcp"
    return response


# ─── Endpoints ─────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"service": "Fakobanko MCP Server", "version": "1.0.0", "protocol": "MCP"}


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {"status": "healthy", "service": "fakobanko-mcp", "session_id": session.session_id}


@app.post("/mcp")
async def mcp_endpoint(request: MCPRequest):
    """Main MCP JSON-RPC endpoint."""
    handlers = {
        "initialize": handle_initialize,
        "tools/list": handle_tools_list,
        "tools/call": handle_tools_call,
        "tools/register": handle_tools_register,
        "resources/list": handle_resources_list,
    }
    
    handler = handlers.get(request.method)
    if not handler:
        return MCPResponse(id=request.id, error={"code": -32601, "message": f"Method not found: {request.method}"})
    
    try:
        result = handler(request.params or {})
        return MCPResponse(id=request.id, result=result)
    except Exception as e:
        return MCPResponse(id=request.id, error={"code": -32603, "message": str(e)})


@app.get("/sse")
async def sse_endpoint():
    """Server-Sent Events endpoint for MCP."""
    async def event_generator():
        yield f"data: {json.dumps({'type': 'connected', 'server': 'fakobanko-mcp'})}\n\n"
        while True:
            await asyncio.sleep(30)
            yield f"data: {json.dumps({'type': 'ping'})}\n\n"
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/.well-known/mcp")
async def mcp_discovery():
    """MCP discovery endpoint."""
    if not is_finding_active("mcp_endpoint_exposed"):
        raise HTTPException(404, "Not found")
    
    return {
        "name": "fakobanko-mcp",
        "version": "1.0.0",
        "endpoints": {"mcp": "/mcp", "sse": "/sse"},
        "capabilities": {"tools": True, "resources": True, "dynamic_tools": is_finding_active("dynamic_tool_loading")}
    }
