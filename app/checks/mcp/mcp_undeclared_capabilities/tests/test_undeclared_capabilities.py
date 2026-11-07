"""Tests for mcp_undeclared_capabilities."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_undeclared_capabilities import UndeclaredCapabilityCheck
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


class TestUndeclaredCapabilityCheck:
    @pytest.fixture
    def check(self):
        return UndeclaredCapabilityCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_undeclared_capabilities"

    @pytest.mark.asyncio
    async def test_undeclared_tools_accessible(self, check):
        """Server declares only resources, but tools/list returns real tool data -- should flag as high."""
        svc = Service(
            url="http://test:8080", host="test", port=8080, scheme="http", service_type="ai"
        )
        ctx = {
            "mcp_servers": [
                {
                    "url": "http://test:8080/mcp",
                    "path": "/mcp",
                    "transport": "http",
                    "capabilities": ["resources"],  # Only resources declared
                    "auth_required": False,
                    "service": svc.to_dict(),
                }
            ]
        }
        mock = mock_client_factory()

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            method = body.get("method", "")
            if method == "tools/list":
                # Realistic tools/list response with multiple tools and full schema
                return make_response(
                    body=json.dumps(
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
                                            "required": ["path"],
                                        },
                                    },
                                    {
                                        "name": "list_dir",
                                        "description": "List directory contents",
                                        "inputSchema": {
                                            "type": "object",
                                            "properties": {"path": {"type": "string"}},
                                        },
                                    },
                                ]
                            },
                        }
                    )
                )
            # All other methods: JSON-RPC method-not-found error
            return make_response(
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {"code": -32601, "message": "Method not found"},
                    }
                )
            )

        mock.post = mock_post

        with patch(
            "app.checks.mcp.mcp_undeclared_capabilities.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, ctx)

        assert result.success
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) == 1
        assert "undeclared capability accessible" in high[0].title.lower()
        assert "tools/list" in high[0].title
        assert "tools" in high[0].evidence.lower()

    @pytest.mark.asyncio
    async def test_all_rejected(self, check, mcp_server_context):
        """When all probed methods return method-not-found, should produce info observation."""
        mock = mock_client_factory()
        mock.post = AsyncMock(
            return_value=make_response(
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {"code": -32601, "message": "Method not found"},
                    }
                )
            )
        )

        with patch(
            "app.checks.mcp.mcp_undeclared_capabilities.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "correctly rejects" in info[0].title.lower()
        # No high or medium findings
        assert not [f for f in result.observations if f.severity in ("high", "medium")]

    @pytest.mark.asyncio
    async def test_declared_capability_not_probed(self, check):
        """When tools are already declared, tools/list should NOT be probed (it is skipped)."""
        svc = Service(
            url="http://test:8080", host="test", port=8080, scheme="http", service_type="ai"
        )
        ctx = {
            "mcp_servers": [
                {
                    "url": "http://test:8080/mcp",
                    "path": "/mcp",
                    "transport": "http",
                    "capabilities": ["tools", "resources", "prompts"],  # All declared
                    "auth_required": False,
                    "service": svc.to_dict(),
                }
            ]
        }
        mock = mock_client_factory()
        probed_methods = []

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            method = body.get("method", "")
            probed_methods.append(method)
            return make_response(
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {"code": -32601, "message": "Method not found"},
                    }
                )
            )

        mock.post = mock_post

        with patch(
            "app.checks.mcp.mcp_undeclared_capabilities.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, ctx)

        assert result.success
        # tools/list, resources/list, prompts/list should NOT be probed since they are declared
        assert "tools/list" not in probed_methods
        assert "resources/list" not in probed_methods
        assert "prompts/list" not in probed_methods
