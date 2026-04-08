"""Tests for MCP vulnerability detection checks: auth, websocket, schema leakage, notification injection."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.auth_check import MCPAuthCheck
from app.checks.mcp.notification_injection import MCPNotificationInjectionCheck
from app.checks.mcp.schema_leakage import ToolSchemaLeakageCheck
from app.checks.mcp.websocket_transport import WebSocketTransportCheck
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Shared Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


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


# ═══════════════════════════════════════════════════════════════════════════════
# MCPAuthCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestMCPAuthCheck:
    @pytest.fixture
    def check(self):
        return MCPAuthCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_auth_check"
        assert "mcp_auth_status" in check.produces

    @pytest.mark.asyncio
    async def test_no_auth_detected(self, check, mcp_server_context):
        mock = mock_client_factory()
        tools_body = json.dumps({"jsonrpc": "2.0", "result": {"tools": [{"name": "test"}]}})
        mock.post = AsyncMock(return_value=make_response(body=tools_body))
        mock.options = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.auth_check.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_auth_enforced(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.options = AsyncMock(return_value=make_response(status_code=401))

        with patch("app.checks.mcp.auth_check.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) > 0

    @pytest.mark.asyncio
    async def test_cors_open(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.options = AsyncMock(
            return_value=make_response(headers={"Access-Control-Allow-Origin": "*"})
        )

        with patch("app.checks.mcp.auth_check.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        cors = [
            f
            for f in result.observations
            if "cors" in f.title.lower() or "cross-origin" in f.title.lower()
        ]
        assert len(cors) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocketTransportCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestWebSocketTransportCheck:
    @pytest.fixture
    def check(self):
        return WebSocketTransportCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_websocket_transport"
        assert "mcp_websocket_servers" in check.produces

    @pytest.mark.asyncio
    async def test_ws_discovered(self, check, mcp_server_context):
        mock = mock_client_factory()

        async def mock_get(url, **kwargs):
            if "/ws" in url:
                return make_response(status_code=101)
            return make_response(status_code=404)

        mock.get = mock_get

        with patch("app.checks.mcp.websocket_transport.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        assert "mcp_websocket_servers" in result.outputs
        ws_observations = [f for f in result.observations if "websocket" in f.title.lower()]
        assert len(ws_observations) > 0

    @pytest.mark.asyncio
    async def test_ws_not_found(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.websocket_transport.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) > 0

    @pytest.mark.asyncio
    async def test_ws_auth_bypass(self, check):
        """WS discovered when HTTP requires auth → high severity."""
        svc = Service(
            url="http://test:8080", host="test", port=8080, scheme="http", service_type="ai"
        )
        ctx = {
            "mcp_servers": [
                {
                    "url": "http://test:8080/mcp",
                    "path": "/mcp",
                    "transport": "http",
                    "capabilities": ["tools"],
                    "auth_required": True,
                    "service": svc.to_dict(),
                }
            ]
        }
        mock = mock_client_factory()

        async def mock_get(url, **kwargs):
            if "/ws" in url:
                return make_response(status_code=101)
            return make_response(status_code=404)

        mock.get = mock_get

        with patch("app.checks.mcp.websocket_transport.AsyncHttpClient", return_value=mock):
            result = await check.run(ctx)

        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# ToolSchemaLeakageCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestToolSchemaLeakageCheck:
    @pytest.fixture
    def check(self):
        return ToolSchemaLeakageCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_schema_leakage"
        assert "mcp_schema_leaks" in check.produces

    @pytest.mark.asyncio
    async def test_detects_sensitive_defaults(self, check):
        ctx = {
            "mcp_tools": [
                {
                    "name": "db_query",
                    "description": "Query database",
                    "input_schema": {
                        "properties": {
                            "db_host": {"type": "string", "default": "prod-db.internal:5432"},
                            "table": {
                                "type": "string",
                                "enum": ["users", "transactions", "api_keys"],
                            },
                        },
                    },
                    "service_host": "test",
                }
            ]
        }
        result = await check.run(ctx)
        assert result.success
        assert "mcp_schema_leaks" in result.outputs
        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) >= 1  # default + enum

    @pytest.mark.asyncio
    async def test_detects_sensitive_param_names(self, check):
        ctx = {
            "mcp_tools": [
                {
                    "name": "admin_tool",
                    "description": "Admin tool",
                    "input_schema": {
                        "properties": {
                            "api_key": {"type": "string"},
                            "bucket_name": {"type": "string"},
                        },
                    },
                    "service_host": "test",
                }
            ]
        }
        result = await check.run(ctx)
        low = [f for f in result.observations if f.severity == "low"]
        assert len(low) >= 2

    @pytest.mark.asyncio
    async def test_no_leaks(self, check):
        ctx = {
            "mcp_tools": [
                {
                    "name": "get_time",
                    "description": "Get time",
                    "input_schema": {"properties": {"format": {"type": "string"}}},
                    "service_host": "test",
                }
            ]
        }
        result = await check.run(ctx)
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# MCPNotificationInjectionCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestMCPNotificationInjectionCheck:
    @pytest.fixture
    def check(self):
        return MCPNotificationInjectionCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_notification_injection"

    @pytest.mark.asyncio
    async def test_notifications_accepted(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=200))

        with patch("app.checks.mcp.notification_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) > 0  # roots/list_changed or tools/list_changed

    @pytest.mark.asyncio
    async def test_notifications_rejected(self, check, mcp_server_context):
        mock = mock_client_factory()
        error_body = json.dumps({"error": {"code": -32601, "message": "Method not found"}})
        mock.post = AsyncMock(return_value=make_response(status_code=200, body=error_body))

        with patch("app.checks.mcp.notification_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) > 0
