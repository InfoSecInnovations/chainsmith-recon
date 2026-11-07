"""Tests for mcp_tool_invocation."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_tool_invocation import MCPToolInvocationCheck
from app.lib.http import HttpResponse


async def run_and_grade(check, context):
    """Run the check, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.run(context)
    return await grade_result(check, result, context)


@pytest.fixture
def sample_service():
    return Service(
        url="http://mcp.example.com:8080",
        host="mcp.example.com",
        port=8080,
        scheme="http",
        service_type="ai",
    )


@pytest.fixture
def mcp_server_context(sample_service):
    return {
        "mcp_servers": [
            {
                "url": "http://mcp.example.com:8080/mcp",
                "path": "/mcp",
                "transport": "http",
                "capabilities": ["tools", "resources"],
                "auth_required": False,
                "server_info": {"name": "test-server", "version": "1.0"},
                "service": sample_service.to_dict(),
            }
        ]
    }


@pytest.fixture
def mcp_tools_context(mcp_server_context):
    ctx = dict(mcp_server_context)
    ctx["mcp_tools"] = [
        {
            "name": "read_file",
            "description": "Read a file from disk",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            "risk_level": "high",
            "service_host": "mcp.example.com",
            "server_url": "http://mcp.example.com:8080/mcp",
        },
        {
            "name": "execute_command",
            "description": "Execute shell command",
            "input_schema": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
            "risk_level": "critical",
            "service_host": "mcp.example.com",
            "server_url": "http://mcp.example.com:8080/mcp",
        },
        {
            "name": "http_fetch",
            "description": "Fetch a URL",
            "input_schema": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
            "risk_level": "high",
            "service_host": "mcp.example.com",
            "server_url": "http://mcp.example.com:8080/mcp",
        },
        {
            "name": "send_email",
            "description": "Send an email message",
            "input_schema": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "body": {"type": "string"},
                },
            },
            "risk_level": "high",
            "service_host": "mcp.example.com",
            "server_url": "http://mcp.example.com:8080/mcp",
        },
        {
            "name": "get_time",
            "description": "Get current time",
            "input_schema": {},
            "risk_level": "info",
            "service_host": "mcp.example.com",
            "server_url": "http://mcp.example.com:8080/mcp",
        },
    ]
    return ctx


def make_response(status_code=200, headers=None, body="", error=None):
    return HttpResponse(
        url="http://test",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=10.0,
        error=error,
    )


def mock_client_factory():
    """Create a properly configured mock client with context manager."""
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


class TestMCPToolInvocationCheck:
    @pytest.fixture
    def check(self):
        return MCPToolInvocationCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_tool_invocation"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_exec_tool_detected(self, check, mcp_tools_context):
        """When a tool returns real system output in a JSON-RPC response, flag as critical."""
        mock = mock_client_factory()

        # Realistic JSON-RPC response with system output embedded among other fields
        exec_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": "Process started (pid 4821)\nchainsmith-probe\nuid=0(root) gid=0(root) groups=0(root)\nexit code: 0",
                        }
                    ],
                    "isError": False,
                },
            }
        )
        mock.post = AsyncMock(return_value=make_response(body=exec_body))

        with patch("app.checks.mcp.mcp_tool_invocation.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, mcp_tools_context)

        assert result.success
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) >= 1
        exec_obs = [f for f in critical if "executes commands" in f.title.lower()]
        assert len(exec_obs) >= 1
        assert "execute_command" in exec_obs[0].title
        assert "chainsmith-probe" in exec_obs[0].evidence

    @pytest.mark.asyncio
    async def test_auth_required_tool(self, check, mcp_tools_context):
        """Tools returning 403 should be flagged as medium with 'requires auth' title."""
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=403))

        with patch("app.checks.mcp.mcp_tool_invocation.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, mcp_tools_context)

        assert result.success
        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) >= 1
        assert all("requires auth" in f.title.lower() for f in medium)
        assert all("403" in f.evidence for f in medium)

    @pytest.mark.asyncio
    async def test_benign_tool_no_critical(self, check):
        """A low-risk tool returning generic output should not produce critical findings."""
        ctx = {
            "mcp_servers": [
                {
                    "url": "http://mcp.example.com:8080/mcp",
                    "path": "/mcp",
                    "transport": "http",
                    "capabilities": ["tools"],
                    "auth_required": False,
                    "service": {
                        "host": "mcp.example.com",
                        "url": "http://mcp.example.com:8080",
                    },
                }
            ],
            "mcp_tools": [
                {
                    "name": "get_time",
                    "description": "Get current time",
                    "input_schema": {},
                    "risk_level": "info",
                    "service_host": "mcp.example.com",
                    "server_url": "http://mcp.example.com:8080/mcp",
                },
            ],
        }
        mock = mock_client_factory()
        benign_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [{"type": "text", "text": "2026-04-08T14:30:00Z"}],
                    "isError": False,
                },
            }
        )
        mock.post = AsyncMock(return_value=make_response(body=benign_body))

        with patch("app.checks.mcp.mcp_tool_invocation.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, ctx)

        assert result.success
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 0
