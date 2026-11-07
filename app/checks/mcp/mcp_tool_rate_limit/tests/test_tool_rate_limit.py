"""Tests for mcp_tool_rate_limit."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_tool_rate_limit import ToolRateLimitCheck
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


class TestToolRateLimitCheck:
    @pytest.fixture
    def check(self):
        return ToolRateLimitCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_tool_rate_limit"

    @pytest.mark.asyncio
    async def test_no_rate_limit_produces_medium(self, check, mcp_tools_context):
        """When all burst requests succeed (200), the check should flag missing rate limiting as medium."""
        mock = mock_client_factory()
        # Realistic response body with varying content to simulate real tool calls
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": call_count,
                    "result": {
                        "content": [
                            {"type": "text", "text": f"Current time: 14:30:{call_count:02d}Z"}
                        ],
                        "isError": False,
                    },
                }
            )
            return make_response(body=body)

        mock.post = mock_post

        with patch("app.checks.mcp.mcp_tool_rate_limit.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, mcp_tools_context)

        assert result.success
        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) == 1
        assert "no per-tool rate limiting" in medium[0].title.lower()
        assert "get_time" in medium[0].title  # should pick the lowest-risk tool
        assert "All succeeded with status 200" in medium[0].evidence

    @pytest.mark.asyncio
    async def test_rate_limited_service_produces_info(self, check, mcp_tools_context):
        """When the server returns 429 after some requests, the check should produce info (not medium)."""
        mock = mock_client_factory()
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count > 3:
                return make_response(status_code=429)
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": call_count,
                    "result": {
                        "content": [{"type": "text", "text": f"Time: 14:30:{call_count:02d}"}],
                    },
                }
            )
            return make_response(body=body)

        mock.post = mock_post

        with patch("app.checks.mcp.mcp_tool_rate_limit.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, mcp_tools_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "rate limiting detected" in info[0].title.lower()
        assert "429" not in info[0].title  # title describes the tool, not the status
        # Should NOT produce any medium findings since rate limiting IS present
        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) == 0
