"""Tests for mcp_auth_check."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_auth_check import MCPAuthCheck
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
def mcp_server_context_auth_required(sample_service):
    """MCP server that requires authentication."""
    return {
        "mcp_servers": [
            {
                "url": "http://mcp.example.com:8080/mcp",
                "path": "/mcp",
                "transport": "http",
                "capabilities": ["tools", "resources"],
                "auth_required": True,
                "server_info": {"name": "test-server", "version": "1.0"},
                "service": sample_service.to_dict(),
            }
        ]
    }


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


class TestMCPAuthCheck:
    @pytest.fixture
    def check(self):
        return MCPAuthCheck()

    @pytest.mark.asyncio
    async def test_no_auth_tools_accessible(self, check, mcp_server_context):
        """Server returns tools without auth -> critical finding about unauthenticated tool access."""
        mock = mock_client_factory()
        tools_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Read a file from disk",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                            },
                        }
                    ]
                },
            }
        )
        mock.post = AsyncMock(return_value=make_response(status_code=200, body=tools_body))
        mock.options = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.mcp_auth_check.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 1
        assert "no authentication" in critical[0].title.lower()
        assert "tools accessible without credentials" in critical[0].title.lower()
        assert "200" in critical[0].evidence

    @pytest.mark.asyncio
    async def test_auth_enforced_returns_zero_critical(self, check, mcp_server_context):
        """Server returns 401 on all endpoints -> info finding, zero critical or high findings."""
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.options = AsyncMock(return_value=make_response(status_code=401))

        with patch("app.checks.mcp.mcp_auth_check.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 0
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) == 0
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) >= 1
        assert "enforces authentication" in info[0].title.lower()

    @pytest.mark.asyncio
    async def test_cors_open(self, check, mcp_server_context):
        """CORS wildcard on MCP endpoint -> high finding about cross-origin requests."""
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.options = AsyncMock(
            return_value=make_response(headers={"Access-Control-Allow-Origin": "*"})
        )

        with patch("app.checks.mcp.mcp_auth_check.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        cors = [f for f in result.observations if "cross-origin" in f.title.lower()]
        assert len(cors) == 1
        assert cors[0].severity == "high"
        assert "Access-Control-Allow-Origin: *" in cors[0].evidence
