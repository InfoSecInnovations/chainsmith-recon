"""Tests for MCP injection checks: resource traversal, template injection, prompt injection, sampling abuse."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.prompt_injection import MCPPromptInjectionCheck
from app.checks.mcp.resource_traversal import MCPResourceTraversalCheck
from app.checks.mcp.sampling_abuse import MCPSamplingAbuseCheck
from app.checks.mcp.template_injection import ResourceTemplateInjectionCheck
from app.lib.http import HttpResponse


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
    mock.__aexit__ = AsyncMock()
    return mock


class TestMCPResourceTraversalCheck:
    @pytest.fixture
    def check(self):
        return MCPResourceTraversalCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_resource_traversal"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_traversal_detected(self, check, mcp_server_context):
        mock = mock_client_factory()

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            params = body.get("params", {})
            uri = params.get("uri", "")
            if "passwd" in uri:
                return make_response(
                    body=json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "result": {"contents": [{"text": "root:x:0:0:root:/root:/bin/bash"}]},
                        }
                    )
                )
            return make_response(body=json.dumps({"jsonrpc": "2.0", "result": {}}))

        mock.post = mock_post

        with patch("app.checks.mcp.resource_traversal.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_traversal_blocked(self, check, mcp_server_context):
        mock = mock_client_factory()
        error_body = json.dumps(
            {"jsonrpc": "2.0", "error": {"code": -1, "message": "Access denied"}}
        )
        mock.post = AsyncMock(return_value=make_response(body=error_body))

        with patch("app.checks.mcp.resource_traversal.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) > 0


class TestResourceTemplateInjectionCheck:
    @pytest.fixture
    def check(self):
        return ResourceTemplateInjectionCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_template_injection"

    @pytest.mark.asyncio
    async def test_sql_injection_detected(self, check, mcp_server_context):
        mock = mock_client_factory()

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            body = kwargs.get("json", {})
            method = body.get("method", "")

            if method == "resources/templates/list":
                return make_response(
                    body=json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "result": {
                                "resourceTemplates": [
                                    {"uriTemplate": "db://query/{table}", "name": "db_query"},
                                ]
                            },
                        }
                    )
                )
            elif method == "resources/read":
                uri = body.get("params", {}).get("uri", "")
                if "OR" in uri or "SELECT" in uri or "UNION" in uri:
                    return make_response(
                        body=json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "error": {"code": -1, "message": "SQL syntax error near 'OR'"},
                            }
                        )
                    )
                return make_response(body=json.dumps({"jsonrpc": "2.0", "result": {}}))

            return make_response(status_code=404)

        mock.post = mock_post

        with patch("app.checks.mcp.template_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        # Should find SQL injection based on error
        high_or_critical = [f for f in result.observations if f.severity in ("high", "critical")]
        assert len(high_or_critical) > 0

    @pytest.mark.asyncio
    async def test_no_templates(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(
            return_value=make_response(
                body=json.dumps({"jsonrpc": "2.0", "result": {"resourceTemplates": []}})
            )
        )

        with patch("app.checks.mcp.template_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success


class TestMCPPromptInjectionCheck:
    @pytest.fixture
    def check(self):
        return MCPPromptInjectionCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_prompt_injection"

    @pytest.mark.asyncio
    async def test_no_text_tools(self, check):
        ctx = {
            "mcp_tools": [
                {
                    "name": "get_time",
                    "description": "Get time",
                    "service_host": "test",
                    "server_url": "http://test/mcp",
                },
            ],
            "mcp_servers": [{"url": "http://test/mcp", "service": {"host": "test"}}],
        }
        result = await check.run(ctx)
        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) > 0

    @pytest.mark.asyncio
    async def test_unfiltered_content_detected(self, check, mcp_tools_context):
        mock = mock_client_factory()
        html_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "result": {
                    "content": [
                        {"type": "text", "text": "<html><body><p>Hello world</p></body></html>"}
                    ]
                },
            }
        )
        mock.post = AsyncMock(return_value=make_response(body=html_body))

        with patch("app.checks.mcp.prompt_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_tools_context)

        assert result.success
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) > 0


class TestMCPSamplingAbuseCheck:
    @pytest.fixture
    def check(self):
        return MCPSamplingAbuseCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_sampling_abuse"

    @pytest.mark.asyncio
    async def test_sampling_exposed(self, check, mcp_server_context):
        mock = mock_client_factory()
        sampling_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "result": {"content": {"type": "text", "text": "Hello! How can I help?"}},
            }
        )
        mock.post = AsyncMock(return_value=make_response(body=sampling_body))

        with patch("app.checks.mcp.sampling_abuse.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) > 0

    @pytest.mark.asyncio
    async def test_sampling_not_available(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.sampling_abuse.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
