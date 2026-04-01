"""
Tests for MCP suite enhanced checks (auth, transport, chain analysis,
schema leakage, fingerprinting, invocation probing, resource traversal,
template injection, prompt injection, sampling, protocol version, rate
limiting, undeclared capabilities, shadow tools, notifications, WebSocket).

Covers 16 checks + the invocation safety framework.
All HTTP calls are mocked.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.lib.http import HttpResponse

# Wave 1
from app.checks.mcp.auth_check import MCPAuthCheck
from app.checks.mcp.websocket_transport import WebSocketTransportCheck
from app.checks.mcp.tool_chain_analysis import ToolChainAnalysisCheck
from app.checks.mcp.shadow_tool_detection import ShadowToolDetectionCheck

# Wave 2
from app.checks.mcp.schema_leakage import ToolSchemaLeakageCheck
from app.checks.mcp.server_fingerprint import MCPServerFingerprintCheck
from app.checks.mcp.transport_security import TransportSecurityCheck
from app.checks.mcp.notification_injection import MCPNotificationInjectionCheck

# Wave 3
from app.checks.mcp.tool_invocation import MCPToolInvocationCheck
from app.checks.mcp.resource_traversal import MCPResourceTraversalCheck
from app.checks.mcp.template_injection import ResourceTemplateInjectionCheck

# Wave 4
from app.checks.mcp.prompt_injection import MCPPromptInjectionCheck

# Wave 5
from app.checks.mcp.sampling_abuse import MCPSamplingAbuseCheck
from app.checks.mcp.protocol_version import MCPProtocolVersionCheck
from app.checks.mcp.rate_limit import ToolRateLimitCheck
from app.checks.mcp.undeclared_capabilities import UndeclaredCapabilityCheck

# Safety framework
from app.checks.mcp.invocation_safety import (
    build_safe_payload, build_probe_payload, is_payload_safe,
    cap_response, classify_tool_probe_type,
)


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
# Wave 1: MCPAuthCheck
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
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_auth_enforced(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.options = AsyncMock(return_value=make_response(status_code=401))

        with patch("app.checks.mcp.auth_check.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) > 0

    @pytest.mark.asyncio
    async def test_cors_open(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.options = AsyncMock(return_value=make_response(
            headers={"Access-Control-Allow-Origin": "*"}
        ))

        with patch("app.checks.mcp.auth_check.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        cors = [f for f in result.findings if "cors" in f.title.lower() or "cross-origin" in f.title.lower()]
        assert len(cors) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 1: WebSocketTransportCheck
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
        ws_findings = [f for f in result.findings if "websocket" in f.title.lower()]
        assert len(ws_findings) > 0

    @pytest.mark.asyncio
    async def test_ws_not_found(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.websocket_transport.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) > 0

    @pytest.mark.asyncio
    async def test_ws_auth_bypass(self, check):
        """WS discovered when HTTP requires auth → high severity."""
        svc = Service(url="http://test:8080", host="test", port=8080, scheme="http", service_type="ai")
        ctx = {
            "mcp_servers": [{
                "url": "http://test:8080/mcp",
                "path": "/mcp",
                "transport": "http",
                "capabilities": ["tools"],
                "auth_required": True,
                "service": svc.to_dict(),
            }]
        }
        mock = mock_client_factory()

        async def mock_get(url, **kwargs):
            if "/ws" in url:
                return make_response(status_code=101)
            return make_response(status_code=404)

        mock.get = mock_get

        with patch("app.checks.mcp.websocket_transport.AsyncHttpClient", return_value=mock):
            result = await check.run(ctx)

        high = [f for f in result.findings if f.severity == "high"]
        assert len(high) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 1: ToolChainAnalysisCheck
# ═══════════════════════════════════════════════════════════════════════════════

class TestToolChainAnalysisCheck:
    @pytest.fixture
    def check(self):
        return ToolChainAnalysisCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_tool_chain_analysis"
        assert "mcp_dangerous_chains" in check.produces

    @pytest.mark.asyncio
    async def test_detects_data_exfil_chain(self, check, mcp_tools_context):
        """read_file + send_email = data exfil chain."""
        result = await check.run(mcp_tools_context)
        assert result.success
        assert "mcp_dangerous_chains" in result.outputs
        chains = result.outputs["mcp_dangerous_chains"]
        assert any("exfil" in c["chain_name"].lower() or "read" in c["chain_name"].lower() for c in chains)

    @pytest.mark.asyncio
    async def test_detects_rce_chain(self, check, mcp_tools_context):
        """read_file + execute_command = file access + code exec."""
        result = await check.run(mcp_tools_context)
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_no_chains_for_benign_tools(self, check):
        ctx = {
            "mcp_tools": [
                {"name": "get_time", "description": "Get time", "service_host": "test"},
                {"name": "format_text", "description": "Format text", "service_host": "test"},
            ]
        }
        result = await check.run(ctx)
        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 1: ShadowToolDetectionCheck
# ═══════════════════════════════════════════════════════════════════════════════

class TestShadowToolDetectionCheck:
    @pytest.fixture
    def check(self):
        return ShadowToolDetectionCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_shadow_tool_detection"
        assert "mcp_shadow_tool_risk" in check.produces

    @pytest.mark.asyncio
    async def test_flat_names_flagged(self, check, mcp_tools_context):
        """Flat tool names should be flagged as medium."""
        result = await check.run(mcp_tools_context)
        assert result.success
        flat_findings = [f for f in result.findings if "flat" in f.title.lower()]
        assert len(flat_findings) > 0

    @pytest.mark.asyncio
    async def test_namespaced_tools_safe(self, check):
        ctx = {
            "mcp_tools": [
                {"name": "server/read_file", "description": "Read", "service_host": "test"},
                {"name": "server/write_file", "description": "Write", "service_host": "test"},
            ],
            "mcp_servers": [],
        }
        result = await check.run(ctx)
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) > 0

    @pytest.mark.asyncio
    async def test_collision_candidates_detected(self, check, mcp_tools_context):
        """read_file, search, send_email should match common names."""
        result = await check.run(mcp_tools_context)
        shadow_risk = result.outputs.get("mcp_shadow_tool_risk", {})
        assert len(shadow_risk.get("collision_candidates", [])) > 0

    @pytest.mark.asyncio
    async def test_list_changed_notification(self, check, mcp_tools_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=200))

        with patch("app.checks.mcp.shadow_tool_detection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_tools_context)

        high = [f for f in result.findings if f.severity == "high"]
        assert any("list_changed" in f.title.lower() or "re-registration" in f.title.lower() for f in high)


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 2: ToolSchemaLeakageCheck
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
            "mcp_tools": [{
                "name": "db_query",
                "description": "Query database",
                "input_schema": {
                    "properties": {
                        "db_host": {"type": "string", "default": "prod-db.internal:5432"},
                        "table": {"type": "string", "enum": ["users", "transactions", "api_keys"]},
                    },
                },
                "service_host": "test",
            }]
        }
        result = await check.run(ctx)
        assert result.success
        assert "mcp_schema_leaks" in result.outputs
        medium = [f for f in result.findings if f.severity == "medium"]
        assert len(medium) >= 1  # default + enum

    @pytest.mark.asyncio
    async def test_detects_sensitive_param_names(self, check):
        ctx = {
            "mcp_tools": [{
                "name": "admin_tool",
                "description": "Admin tool",
                "input_schema": {
                    "properties": {
                        "api_key": {"type": "string"},
                        "bucket_name": {"type": "string"},
                    },
                },
                "service_host": "test",
            }]
        }
        result = await check.run(ctx)
        low = [f for f in result.findings if f.severity == "low"]
        assert len(low) >= 2

    @pytest.mark.asyncio
    async def test_no_leaks(self, check):
        ctx = {
            "mcp_tools": [{
                "name": "get_time",
                "description": "Get time",
                "input_schema": {"properties": {"format": {"type": "string"}}},
                "service_host": "test",
            }]
        }
        result = await check.run(ctx)
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 2: MCPServerFingerprintCheck
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPServerFingerprintCheck:
    @pytest.fixture
    def check(self):
        return MCPServerFingerprintCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_server_fingerprint"

    @pytest.mark.asyncio
    async def test_fingerprint_from_server_info(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.server_fingerprint.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        assert "mcp_server_implementations" in result.outputs

    @pytest.mark.asyncio
    async def test_fingerprint_from_error(self, check):
        svc = Service(url="http://test:8080", host="test", port=8080, scheme="http", service_type="ai")
        ctx = {
            "mcp_servers": [{
                "url": "http://test:8080/mcp",
                "path": "/mcp",
                "transport": "http",
                "capabilities": [],
                "auth_required": False,
                "server_info": {},
                "service": svc.to_dict(),
            }]
        }
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(
            body='{"error": "McpError: method not found", "code": -32601}'
        ))

        with patch("app.checks.mcp.server_fingerprint.AsyncHttpClient", return_value=mock):
            result = await check.run(ctx)

        assert result.success


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 2: TransportSecurityCheck
# ═══════════════════════════════════════════════════════════════════════════════

class TestTransportSecurityCheck:
    @pytest.fixture
    def check(self):
        return TransportSecurityCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_transport_security"

    @pytest.mark.asyncio
    async def test_plain_http_flagged(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.options = AsyncMock(return_value=make_response(status_code=404))
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.transport_security.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        high = [f for f in result.findings if f.severity == "high"]
        assert any("plain http" in f.title.lower() or "no tls" in f.title.lower() for f in high)

    @pytest.mark.asyncio
    async def test_cors_wildcard(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.options = AsyncMock(return_value=make_response(
            headers={"Access-Control-Allow-Origin": "*"}
        ))
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.transport_security.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        cors = [f for f in result.findings if "cors" in f.title.lower()]
        assert len(cors) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 2: MCPNotificationInjectionCheck
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
        high = [f for f in result.findings if f.severity == "high"]
        assert len(high) > 0  # roots/list_changed or tools/list_changed

    @pytest.mark.asyncio
    async def test_notifications_rejected(self, check, mcp_server_context):
        mock = mock_client_factory()
        error_body = json.dumps({"error": {"code": -32601, "message": "Method not found"}})
        mock.post = AsyncMock(return_value=make_response(status_code=200, body=error_body))

        with patch("app.checks.mcp.notification_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 3: MCPToolInvocationCheck
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPToolInvocationCheck:
    @pytest.fixture
    def check(self):
        return MCPToolInvocationCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_tool_invocation"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_exec_tool_detected(self, check, mcp_tools_context):
        mock = mock_client_factory()
        exec_body = json.dumps({
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": "chainsmith-probe\nroot"}]},
        })
        mock.post = AsyncMock(return_value=make_response(body=exec_body))

        with patch("app.checks.mcp.tool_invocation.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_tools_context)

        assert result.success
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_auth_required_tool(self, check, mcp_tools_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=403))

        with patch("app.checks.mcp.tool_invocation.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_tools_context)

        assert result.success
        medium = [f for f in result.findings if f.severity == "medium"]
        assert len(medium) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 3: MCPResourceTraversalCheck
# ═══════════════════════════════════════════════════════════════════════════════

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
                return make_response(body=json.dumps({
                    "jsonrpc": "2.0",
                    "result": {"contents": [{"text": "root:x:0:0:root:/root:/bin/bash"}]},
                }))
            return make_response(body=json.dumps({"jsonrpc": "2.0", "result": {}}))

        mock.post = mock_post

        with patch("app.checks.mcp.resource_traversal.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_traversal_blocked(self, check, mcp_server_context):
        mock = mock_client_factory()
        error_body = json.dumps({"jsonrpc": "2.0", "error": {"code": -1, "message": "Access denied"}})
        mock.post = AsyncMock(return_value=make_response(body=error_body))

        with patch("app.checks.mcp.resource_traversal.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 3: ResourceTemplateInjectionCheck
# ═══════════════════════════════════════════════════════════════════════════════

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
                return make_response(body=json.dumps({
                    "jsonrpc": "2.0",
                    "result": {"resourceTemplates": [
                        {"uriTemplate": "db://query/{table}", "name": "db_query"},
                    ]},
                }))
            elif method == "resources/read":
                uri = body.get("params", {}).get("uri", "")
                if "OR" in uri or "SELECT" in uri or "UNION" in uri:
                    return make_response(body=json.dumps({
                        "jsonrpc": "2.0",
                        "error": {"code": -1, "message": "SQL syntax error near 'OR'"},
                    }))
                return make_response(body=json.dumps({"jsonrpc": "2.0", "result": {}}))

            return make_response(status_code=404)

        mock.post = mock_post

        with patch("app.checks.mcp.template_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        # Should find SQL injection based on error
        high_or_critical = [f for f in result.findings if f.severity in ("high", "critical")]
        assert len(high_or_critical) > 0

    @pytest.mark.asyncio
    async def test_no_templates(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(
            body=json.dumps({"jsonrpc": "2.0", "result": {"resourceTemplates": []}})
        ))

        with patch("app.checks.mcp.template_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 4: MCPPromptInjectionCheck
# ═══════════════════════════════════════════════════════════════════════════════

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
                {"name": "get_time", "description": "Get time", "service_host": "test",
                 "server_url": "http://test/mcp"},
            ],
            "mcp_servers": [{"url": "http://test/mcp", "service": {"host": "test"}}],
        }
        result = await check.run(ctx)
        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) > 0

    @pytest.mark.asyncio
    async def test_unfiltered_content_detected(self, check, mcp_tools_context):
        mock = mock_client_factory()
        html_body = json.dumps({
            "jsonrpc": "2.0",
            "result": {"content": [{"type": "text", "text": "<html><body><p>Hello world</p></body></html>"}]},
        })
        mock.post = AsyncMock(return_value=make_response(body=html_body))

        with patch("app.checks.mcp.prompt_injection.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_tools_context)

        assert result.success
        high = [f for f in result.findings if f.severity == "high"]
        assert len(high) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 5: MCPSamplingAbuseCheck
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPSamplingAbuseCheck:
    @pytest.fixture
    def check(self):
        return MCPSamplingAbuseCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_sampling_abuse"

    @pytest.mark.asyncio
    async def test_sampling_exposed(self, check, mcp_server_context):
        mock = mock_client_factory()
        sampling_body = json.dumps({
            "jsonrpc": "2.0",
            "result": {"content": {"type": "text", "text": "Hello! How can I help?"}},
        })
        mock.post = AsyncMock(return_value=make_response(body=sampling_body))

        with patch("app.checks.mcp.sampling_abuse.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        high = [f for f in result.findings if f.severity == "high"]
        assert len(high) > 0

    @pytest.mark.asyncio
    async def test_sampling_not_available(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.sampling_abuse.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 5: MCPProtocolVersionCheck
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPProtocolVersionCheck:
    @pytest.fixture
    def check(self):
        return MCPProtocolVersionCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_protocol_version"

    @pytest.mark.asyncio
    async def test_downgrade_detected(self, check, mcp_server_context):
        mock = mock_client_factory()

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            version = body.get("params", {}).get("protocolVersion", "")
            return make_response(body=json.dumps({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": version,
                    "capabilities": {"tools": {}} if version >= "2024-11-05" else {},
                },
            }))

        mock.post = mock_post

        with patch("app.checks.mcp.protocol_version.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        assert "mcp_protocol_versions" in result.outputs
        downgrade = [f for f in result.findings if "downgrade" in f.title.lower()]
        assert len(downgrade) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 5: ToolRateLimitCheck
# ═══════════════════════════════════════════════════════════════════════════════

class TestToolRateLimitCheck:
    @pytest.fixture
    def check(self):
        return ToolRateLimitCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_tool_rate_limit"

    @pytest.mark.asyncio
    async def test_no_rate_limit(self, check, mcp_tools_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(
            body=json.dumps({"jsonrpc": "2.0", "result": {"content": [{"text": "ok"}]}})
        ))

        with patch("app.checks.mcp.rate_limit.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_tools_context)

        assert result.success
        medium = [f for f in result.findings if f.severity == "medium"]
        assert len(medium) > 0  # No rate limit = medium

    @pytest.mark.asyncio
    async def test_rate_limit_detected(self, check, mcp_tools_context):
        mock = mock_client_factory()
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count > 5:
                return make_response(status_code=429)
            return make_response(body=json.dumps({"jsonrpc": "2.0", "result": {}}))

        mock.post = mock_post

        with patch("app.checks.mcp.rate_limit.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_tools_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Wave 5: UndeclaredCapabilityCheck
# ═══════════════════════════════════════════════════════════════════════════════

class TestUndeclaredCapabilityCheck:
    @pytest.fixture
    def check(self):
        return UndeclaredCapabilityCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_undeclared_capabilities"

    @pytest.mark.asyncio
    async def test_undeclared_tools_accessible(self, check):
        """Server declares resources but tools/list also works."""
        svc = Service(url="http://test:8080", host="test", port=8080, scheme="http", service_type="ai")
        ctx = {
            "mcp_servers": [{
                "url": "http://test:8080/mcp",
                "path": "/mcp",
                "transport": "http",
                "capabilities": ["resources"],  # Only resources declared
                "auth_required": False,
                "service": svc.to_dict(),
            }]
        }
        mock = mock_client_factory()

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            method = body.get("method", "")
            if method == "tools/list":
                return make_response(body=json.dumps({
                    "jsonrpc": "2.0",
                    "result": {"tools": [{"name": "hidden_tool"}]},
                }))
            return make_response(body=json.dumps({"jsonrpc": "2.0", "error": {"code": -32601}}))

        mock.post = mock_post

        with patch("app.checks.mcp.undeclared_capabilities.AsyncHttpClient", return_value=mock):
            result = await check.run(ctx)

        assert result.success
        high = [f for f in result.findings if f.severity == "high"]
        assert len(high) > 0

    @pytest.mark.asyncio
    async def test_all_rejected(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(
            body=json.dumps({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Not found"}})
        ))

        with patch("app.checks.mcp.undeclared_capabilities.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.findings if f.severity == "info"]
        assert len(info) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Invocation Safety Framework
# ═══════════════════════════════════════════════════════════════════════════════

class TestInvocationSafety:
    def test_build_safe_payload(self):
        tool = {
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "count": {"type": "integer", "minimum": 0},
                },
                "required": ["path"],
            }
        }
        payload = build_safe_payload(tool)
        assert "path" in payload
        assert isinstance(payload["path"], str)

    def test_build_safe_payload_with_enum(self):
        tool = {
            "input_schema": {
                "properties": {"mode": {"type": "string", "enum": ["read", "write"]}},
                "required": ["mode"],
            }
        }
        payload = build_safe_payload(tool)
        assert payload.get("mode") == "read"

    def test_build_probe_payload_file(self):
        tool = {
            "name": "read_file",
            "input_schema": {"properties": {"path": {"type": "string"}}, "required": ["path"]},
        }
        payload = build_probe_payload(tool, "file")
        assert "/etc/hostname" in payload.get("path", "")

    def test_build_probe_payload_exec(self):
        tool = {
            "name": "exec",
            "input_schema": {"properties": {"command": {"type": "string"}}, "required": ["command"]},
        }
        payload = build_probe_payload(tool, "exec")
        assert "chainsmith-probe" in payload.get("command", "")

    def test_is_payload_safe(self):
        assert is_payload_safe({"path": "/etc/hostname"}) is True
        assert is_payload_safe({"command": "echo test"}) is True
        assert is_payload_safe({"command": "rm -rf /"}) is False
        assert is_payload_safe({"query": "DROP TABLE users"}) is False

    def test_cap_response(self):
        short = "hello"
        assert cap_response(short) == "hello"
        long_str = "x" * 2000
        capped = cap_response(long_str)
        assert len(capped) < 2000
        assert "truncated" in capped

    def test_classify_tool_probe_type(self):
        assert classify_tool_probe_type({"name": "read_file", "description": ""}) == "file"
        assert classify_tool_probe_type({"name": "http_fetch", "description": ""}) == "fetch"
        assert classify_tool_probe_type({"name": "execute_command", "description": ""}) == "exec"
        assert classify_tool_probe_type({"name": "sql_query", "description": ""}) == "search"
        assert classify_tool_probe_type({"name": "get_time", "description": ""}) == "generic"
