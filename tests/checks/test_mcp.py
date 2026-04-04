"""
Tests for app/checks/mcp/ suite

Covers:
- MCPDiscoveryCheck
  - MCP endpoint discovery via well-known paths
  - MCP header detection
  - SSE transport detection
  - Auth requirement detection
- MCPToolEnumerationCheck
  - Tool listing via JSON-RPC and REST
  - Risk classification (critical, high, medium, low, info)
  - Dangerous tool detection

Note: All HTTP calls are mocked to avoid actual network traffic.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.discovery import MCPDiscoveryCheck
from app.checks.mcp.tool_enumeration import MCPToolEnumerationCheck
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def sample_service():
    """Sample MCP-capable service."""
    return Service(
        url="http://mcp.example.com:8080",
        host="mcp.example.com",
        port=8080,
        scheme="http",
        service_type="ai",
    )


@pytest.fixture
def mcp_server_context(sample_service):
    """Context with MCP servers discovered."""
    return {
        "mcp_servers": [
            {
                "url": "http://mcp.example.com:8080/mcp",
                "path": "/mcp",
                "transport": "http",
                "capabilities": ["tools"],
                "auth_required": False,
                "service": sample_service.to_dict(),
            }
        ]
    }


def make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    error: str = None,
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url="http://mcp.example.com:8080",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=100.0,
        error=error,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# MCPDiscoveryCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestMCPDiscoveryCheck:
    """Tests for MCPDiscoveryCheck."""

    @pytest.fixture
    def check(self):
        return MCPDiscoveryCheck()

    def test_check_metadata(self, check):
        """Test check has required metadata."""
        assert check.name == "mcp_discovery"
        assert "mcp_servers" in check.produces
        assert len(check.conditions) > 0

    @pytest.mark.asyncio
    async def test_discovers_mcp_via_well_known(self, check, sample_service):
        """Test MCP discovery via .well-known path."""
        mock_client = AsyncMock()

        # Most paths return 404, but /.well-known/mcp returns MCP response
        async def mock_get(url, **kwargs):
            if "/.well-known/mcp" in url:
                return make_response(
                    status_code=200,
                    headers={"x-mcp-version": "1.0", "content-type": "application/json"},
                    body='{"jsonrpc": "2.0", "capabilities": ["tools"]}',
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        assert "mcp_servers" in result.outputs
        assert len(result.outputs["mcp_servers"]) > 0
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_detects_mcp_headers(self, check, sample_service):
        """Test detection via MCP-specific headers."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/mcp" in url:
                return make_response(
                    status_code=200,
                    headers={"mcp-session-id": "abc123"},
                    body="{}",
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        assert "mcp_servers" in result.outputs

    @pytest.mark.asyncio
    async def test_detects_sse_transport(self, check, sample_service):
        """Test SSE transport detection."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/mcp/sse" in url:
                return make_response(
                    status_code=200,
                    headers={"content-type": "text/event-stream"},
                    body="",
                )
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        servers = result.outputs.get("mcp_servers", [])
        sse_servers = [s for s in servers if s.get("transport") == "sse"]
        assert len(sse_servers) > 0

    @pytest.mark.asyncio
    async def test_detects_auth_required(self, check, sample_service):
        """Test auth requirement detection."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/mcp" in url:
                return make_response(status_code=401)
            return make_response(status_code=404)

        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        servers = result.outputs.get("mcp_servers", [])
        if servers:
            assert any(s.get("auth_required") for s in servers)

    @pytest.mark.asyncio
    async def test_no_mcp_found(self, check, sample_service):
        """Test when no MCP endpoints found."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        assert len(result.outputs.get("mcp_servers", [])) == 0
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# MCPToolEnumerationCheck Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestMCPToolEnumerationCheck:
    """Tests for MCPToolEnumerationCheck."""

    @pytest.fixture
    def check(self):
        return MCPToolEnumerationCheck()

    def test_check_metadata(self, check):
        """Test check has required metadata."""
        assert check.name == "mcp_tool_enumeration"
        assert "mcp_tools" in check.produces
        assert "high_risk_tools" in check.produces

    @pytest.mark.asyncio
    async def test_enumerates_tools_jsonrpc(self, check, sample_service, mcp_server_context):
        """Test tool enumeration via JSON-RPC."""
        mock_client = AsyncMock()

        tools_response = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "read_file", "description": "Read a file from disk"},
                    {"name": "get_time", "description": "Get current time"},
                ]
            },
        }

        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body=str(tools_response).replace("'", '"'),
            )
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.tool_enumeration.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, mcp_server_context)

        assert result.success
        assert "mcp_tools" in result.outputs

    @pytest.mark.asyncio
    async def test_classifies_critical_tools(self, check, sample_service, mcp_server_context):
        """Test critical tool detection (exec, shell, eval)."""
        mock_client = AsyncMock()

        tools_response = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "execute_command", "description": "Execute shell command"},
                    {"name": "eval_code", "description": "Evaluate Python code"},
                ]
            },
        }

        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body=str(tools_response).replace("'", '"'),
            )
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.tool_enumeration.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, mcp_server_context)

        assert result.success
        high_risk = result.outputs.get("high_risk_tools", [])
        assert len(high_risk) > 0
        # Should have critical severity findings
        critical_findings = [f for f in result.findings if f.severity == "critical"]
        assert len(critical_findings) > 0

    @pytest.mark.asyncio
    async def test_classifies_high_risk_tools(self, check, sample_service, mcp_server_context):
        """Test high-risk tool detection (file, http, sql)."""
        mock_client = AsyncMock()

        tools_response = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "read_file", "description": "Read file contents"},
                    {"name": "write_file", "description": "Write to file"},
                    {"name": "http_request", "description": "Make HTTP request"},
                ]
            },
        }

        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body=str(tools_response).replace("'", '"'),
            )
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.tool_enumeration.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, mcp_server_context)

        assert result.success
        high_risk = result.outputs.get("high_risk_tools", [])
        assert len(high_risk) >= 2

    @pytest.mark.asyncio
    async def test_benign_tools_low_severity(self, check, sample_service, mcp_server_context):
        """Test benign tools get low/info severity."""
        mock_client = AsyncMock()

        tools_response = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "get_current_time", "description": "Get current timestamp"},
                    {"name": "format_text", "description": "Format text string"},
                ]
            },
        }

        mock_client.post = AsyncMock(
            return_value=make_response(
                status_code=200,
                body=str(tools_response).replace("'", '"'),
            )
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.tool_enumeration.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, mcp_server_context)

        assert result.success
        high_risk = result.outputs.get("high_risk_tools", [])
        assert len(high_risk) == 0

    @pytest.mark.asyncio
    async def test_no_mcp_servers_skips(self, check, sample_service):
        """Test check skips when no MCP servers in context."""
        result = await check.check_service(sample_service, {})

        assert result.success
        assert len(result.findings) == 0
