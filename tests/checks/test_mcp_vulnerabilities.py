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
    mock.__aexit__ = AsyncMock()
    return mock


# ═══════════════════════════════════════════════════════════════════════════════
# MCPAuthCheck
# ═══════════════════════════════════════════════════════════════════════════════


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

        with patch("app.checks.mcp.auth_check.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

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

        with patch("app.checks.mcp.auth_check.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

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

        with patch("app.checks.mcp.auth_check.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        cors = [f for f in result.observations if "cross-origin" in f.title.lower()]
        assert len(cors) == 1
        assert cors[0].severity == "high"
        assert "Access-Control-Allow-Origin: *" in cors[0].evidence


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocketTransportCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestWebSocketTransportCheck:
    @pytest.fixture
    def check(self):
        return WebSocketTransportCheck()

    @pytest.mark.asyncio
    async def test_ws_discovered(self, check, mcp_server_context):
        """WS upgrade returns 101 -> medium finding with ws:// URL in evidence."""
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
        ws_findings = [f for f in result.observations if f.severity == "medium"]
        assert len(ws_findings) == 1
        assert "websocket transport discovered" in ws_findings[0].title.lower()
        assert "101" in ws_findings[0].evidence

    @pytest.mark.asyncio
    async def test_ws_all_404_no_bypass_finding(self, check, mcp_server_context):
        """All WS paths return 404 -> info observation, no medium/high/critical findings."""
        mock = mock_client_factory()
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.websocket_transport.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        assert "mcp_websocket_servers" not in result.outputs
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "rejected" in info[0].title.lower()
        # No bypass or medium+ findings
        serious = [f for f in result.observations if f.severity in ("medium", "high", "critical")]
        assert len(serious) == 0

    @pytest.mark.asyncio
    async def test_ws_auth_bypass(self, check, mcp_server_context_auth_required):
        """WS upgrade succeeds when HTTP requires auth -> high severity auth bypass."""
        mock = mock_client_factory()

        async def mock_get(url, **kwargs):
            if "/ws" in url:
                return make_response(status_code=101)
            return make_response(status_code=404)

        mock.get = mock_get

        with patch("app.checks.mcp.websocket_transport.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context_auth_required)

        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) == 1
        assert "no authentication" in high[0].title.lower()
        assert "http endpoint requires auth" in high[0].title.lower()
        assert "101" in high[0].evidence


# ═══════════════════════════════════════════════════════════════════════════════
# ToolSchemaLeakageCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestToolSchemaLeakageCheck:
    @pytest.fixture
    def check(self):
        return ToolSchemaLeakageCheck()

    @pytest.mark.asyncio
    async def test_detects_sensitive_defaults_and_enums(self, check):
        """Internal hostname default + sensitive enum values -> two medium findings."""
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
        assert len(medium) == 2

        # One for the default value revealing internal hostname
        default_obs = [f for f in medium if "default value" in f.title.lower()]
        assert len(default_obs) == 1
        assert "prod-db.internal:5432" in default_obs[0].title
        assert "db_host" in default_obs[0].evidence

        # One for the enum revealing internal table names
        enum_obs = [f for f in medium if "enum" in f.title.lower()]
        assert len(enum_obs) == 1
        assert "users" in enum_obs[0].evidence or "api_keys" in enum_obs[0].evidence

    @pytest.mark.asyncio
    async def test_detects_sensitive_param_names(self, check):
        """Parameters named api_key and bucket_name -> low findings for each."""
        ctx = {
            "mcp_tools": [
                {
                    "name": "storage_tool",
                    "description": "Manage storage",
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
        assert len(low) == 2
        param_names = {f.raw_data["param"] for f in low}
        assert param_names == {"api_key", "bucket_name"}
        # Verify titles describe what was revealed
        for obs in low:
            assert "reveals" in obs.title.lower()
            assert obs.raw_data["param"] in obs.evidence

    @pytest.mark.asyncio
    async def test_clean_schema_no_leaks(self, check):
        """Benign tool schema with no sensitive params -> info, zero leaks."""
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
        assert result.success
        assert "mcp_schema_leaks" not in result.outputs
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "no sensitive information" in info[0].title.lower()
        # No medium/high/critical findings
        serious = [f for f in result.observations if f.severity in ("medium", "high", "critical")]
        assert len(serious) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# MCPNotificationInjectionCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestMCPNotificationInjectionCheck:
    @pytest.fixture
    def check(self):
        return MCPNotificationInjectionCheck()

    @pytest.mark.asyncio
    async def test_notifications_accepted(self, check, mcp_server_context):
        """Server returns 200 with empty body (no JSON-RPC error) -> notifications accepted."""
        mock = mock_client_factory()
        # Realistic: MCP server accepts notification silently (202 No Content or 200 empty)
        mock.post = AsyncMock(return_value=make_response(status_code=202, body=""))

        with patch("app.checks.mcp.notification_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) == 2
        titles = {f.title for f in high}
        assert any("tools/list_changed" in t for t in titles)
        assert any("roots/list_changed" in t for t in titles)
        # Verify evidence includes the method tested
        for obs in high:
            assert "Method:" in obs.evidence
            assert "accepted" in obs.evidence

    @pytest.mark.asyncio
    async def test_notifications_rejected_via_jsonrpc_error(self, check, mcp_server_context):
        """Server returns 200 but body has JSON-RPC error -> all rejected, info finding."""
        mock = mock_client_factory()
        error_body = json.dumps(
            {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}}
        )
        mock.post = AsyncMock(return_value=make_response(status_code=200, body=error_body))

        with patch("app.checks.mcp.notification_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        # All notifications rejected -> clean info observation
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "rejects unsolicited" in info[0].title.lower()
        # No high/critical findings
        high = [f for f in result.observations if f.severity in ("high", "critical")]
        assert len(high) == 0

    @pytest.mark.asyncio
    async def test_notifications_rejected_via_http_error(self, check, mcp_server_context):
        """Server returns 405 Method Not Allowed -> all rejected, info finding only."""
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=405, body=""))

        with patch("app.checks.mcp.notification_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "rejects" in info[0].title.lower()
        serious = [f for f in result.observations if f.severity in ("medium", "high", "critical")]
        assert len(serious) == 0
