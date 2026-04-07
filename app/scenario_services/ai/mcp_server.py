"""
app/scenario_services/ai/mcp_server.py

Model Context Protocol (MCP) server service template.

This service implements an MCP server with configurable tools, resources,
and security observations. It supports the MCP JSON-RPC protocol and SSE.

Configurable via environment variables:
    BRAND_NAME          Display name (default: from scenario.json)
    MCP_SERVER_NAME     Server identifier (default: <brand>-mcp)
    MCP_VERSION         Protocol version (default: 2024-11-05)

Planted observations:
    mcp_endpoint_exposed        /.well-known/mcp is accessible, sensitive tools visible
    dynamic_tool_loading        Dynamic tool registration enabled
    resource_list_exposed       Sensitive resources in resources/list
    tool_chain_exposed          Tool metadata includes sensitive flags

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.ai.mcp_server:app
      --host 0.0.0.0 --port 8089
    environment:
      - BRAND_NAME=Fakobanko
      - MCP_SERVER_NAME=fakobanko-mcp
"""

import asyncio
import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.scenario_services.common.config import (
    get_brand_name,
    get_or_create_session,
    is_observation_active,
)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

MCP_VERSION = os.getenv("MCP_VERSION", "2024-11-05")


def _get_server_name() -> str:
    if name := os.getenv("MCP_SERVER_NAME"):
        return name
    brand = get_brand_name().lower().replace(" ", "-")
    return f"{brand}-mcp"


# ═══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="MCP Server",
    description="Model Context Protocol server",
    version="1.0.0",
)


# ═══════════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════════


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


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL & RESOURCE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Standard tools - always visible
MCP_TOOLS = [
    {
        "name": "get_customer",
        "description": "Retrieve customer information",
        "inputSchema": {
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
        },
    },
    {
        "name": "search_accounts",
        "description": "Search customer accounts",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
        },
    },
]

# Sensitive tools - exposed when mcp_endpoint_exposed is active
SENSITIVE_TOOLS = [
    {
        "name": "execute_transfer",
        "description": "Execute a fund transfer",
        "sensitive": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "from": {"type": "string"},
                "to": {"type": "string"},
                "amount": {"type": "number"},
            },
        },
    },
    {
        "name": "run_sql",
        "description": "Run SQL query",
        "sensitive": True,
        "dangerous": True,
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
        },
    },
]

# Dynamically registered tools (shadow tools)
DYNAMIC_TOOLS: dict[str, dict] = {}

# Standard resources
MCP_RESOURCES = [
    {
        "uri": "docs://api-reference",
        "name": "API Reference",
        "mimeType": "text/markdown",
    },
]

# Sensitive resources - exposed when resource_list_exposed is active
SENSITIVE_RESOURCES = [
    {
        "uri": "internal://config",
        "name": "Internal Config",
        "mimeType": "application/json",
        "sensitive": True,
    },
    {
        "uri": "internal://credentials",
        "name": "Service Credentials",
        "mimeType": "application/json",
        "sensitive": True,
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# MCP HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════


def handle_initialize(params: dict) -> dict:
    """Handle MCP initialize request."""
    server_name = _get_server_name()

    capabilities = {"tools": {}, "resources": {}}

    # Observation: dynamic_tool_loading - enables shadow tool registration
    if is_observation_active("dynamic_tool_loading"):
        capabilities["tools"]["dynamicRegistration"] = True

    return {
        "protocolVersion": MCP_VERSION,
        "serverInfo": {"name": server_name, "version": "1.0.0"},
        "capabilities": capabilities,
    }


def handle_tools_list(params: dict) -> dict:
    """Handle tools/list request."""
    tools = list(MCP_TOOLS)

    # Observation: mcp_endpoint_exposed - include sensitive tools
    if is_observation_active("mcp_endpoint_exposed"):
        tools.extend(SENSITIVE_TOOLS)

    # Include dynamically registered tools
    tools.extend(DYNAMIC_TOOLS.values())

    return {"tools": tools}


def handle_tools_call(params: dict) -> dict:
    """Handle tools/call request."""
    tool_name = params.get("name", "")
    params.get("arguments", {})

    # Check if it's a shadow tool
    if tool_name in DYNAMIC_TOOLS:
        return {"content": [{"type": "text", "text": f"[SHADOW TOOL] Executed {tool_name}"}]}

    # Simulate tool execution
    return {"content": [{"type": "text", "text": f"Executed {tool_name} successfully."}]}


def handle_tools_register(params: dict) -> dict:
    """
    Handle dynamic tool registration.

    Observation: dynamic_tool_loading
    When active, allows registering arbitrary tools.
    """
    if not is_observation_active("dynamic_tool_loading"):
        raise HTTPException(403, "Dynamic tool registration disabled")

    tool = params.get("tool", {})
    tool_name = tool.get("name")

    if not tool_name:
        raise HTTPException(400, "Tool name required")

    DYNAMIC_TOOLS[tool_name] = tool

    return {"registered": tool_name, "status": "success"}


def handle_resources_list(params: dict) -> dict:
    """Handle resources/list request."""
    resources = list(MCP_RESOURCES)

    # Observation: resource_list_exposed - include sensitive resources
    if is_observation_active("resource_list_exposed"):
        resources.extend(SENSITIVE_RESOURCES)

    return {"resources": resources}


def handle_resources_read(params: dict) -> dict:
    """Handle resources/read request."""
    uri = params.get("uri", "")

    # Simulate resource content
    if uri == "docs://api-reference":
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "text/markdown",
                    "text": "# API Reference\n\nDocumentation for the API.",
                }
            ]
        }

    # Sensitive resources
    if uri.startswith("internal://") and is_observation_active("resource_list_exposed"):
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps({"warning": "Sensitive data", "uri": uri}),
                }
            ]
        }

    raise HTTPException(404, f"Resource not found: {uri}")


# Handler dispatch table
MCP_HANDLERS = {
    "initialize": handle_initialize,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    "tools/register": handle_tools_register,
    "resources/list": handle_resources_list,
    "resources/read": handle_resources_read,
}


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════


@app.middleware("http")
async def add_headers(request: Request, call_next):
    """Add MCP server headers."""
    response = await call_next(request)
    response.headers["X-MCP-Server"] = _get_server_name()
    return response


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/")
async def root():
    """Server info endpoint."""
    server_name = _get_server_name()
    return {
        "service": server_name,
        "version": "1.0.0",
        "protocol": "MCP",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    session = get_or_create_session()
    server_name = _get_server_name()

    return {
        "status": "healthy",
        "service": server_name,
        "session_id": session.session_id,
    }


@app.post("/mcp")
async def mcp_endpoint(request: MCPRequest):
    """
    Main MCP JSON-RPC endpoint.

    Handles all MCP protocol methods via JSON-RPC 2.0.
    """
    handler = MCP_HANDLERS.get(request.method)

    if not handler:
        return MCPResponse(
            id=request.id,
            error={"code": -32601, "message": f"Method not found: {request.method}"},
        )

    try:
        result = handler(request.params or {})
        return MCPResponse(id=request.id, result=result)
    except HTTPException as e:
        return MCPResponse(
            id=request.id,
            error={"code": -32603, "message": e.detail},
        )
    except Exception as e:
        return MCPResponse(
            id=request.id,
            error={"code": -32603, "message": str(e)},
        )


@app.get("/sse")
async def sse_endpoint():
    """
    Server-Sent Events endpoint for MCP.

    Provides a persistent connection for real-time updates.
    """
    server_name = _get_server_name()

    async def event_generator():
        yield f"data: {json.dumps({'type': 'connected', 'server': server_name})}\n\n"
        while True:
            await asyncio.sleep(30)
            yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/.well-known/mcp")
async def mcp_discovery():
    """
    MCP discovery endpoint.

    Observation: mcp_endpoint_exposed
    When active, this endpoint is accessible and reveals server capabilities.
    """
    if not is_observation_active("mcp_endpoint_exposed"):
        raise HTTPException(404, "Not found")

    server_name = _get_server_name()

    return {
        "name": server_name,
        "version": "1.0.0",
        "endpoints": {"mcp": "/mcp", "sse": "/sse"},
        "capabilities": {
            "tools": True,
            "resources": True,
            "dynamic_tools": is_observation_active("dynamic_tool_loading"),
        },
    }
