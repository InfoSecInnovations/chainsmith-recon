"""
Tests for app/checks/mcp/ suite

Covers:
- MCPDiscoveryCheck
  - MCP endpoint discovery via well-known paths
  - MCP header detection
  - SSE transport detection
  - Auth requirement detection
  - Negative: JSON on /mcp without MCP indicators
  - Negative: non-MCP SSE endpoint
- MCPToolEnumerationCheck
  - Tool listing via JSON-RPC and REST
  - Risk classification (critical, high, medium, low, info)
  - Dangerous tool detection
  - Specific title, severity, and evidence assertions

Note: All HTTP calls are mocked to avoid actual network traffic.
"""

import json
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
    url: str = "http://mcp.example.com:8080",
    error: str = None,
) -> HttpResponse:
    """Create a mock HTTP response."""
    return HttpResponse(
        url=url,
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
        assert check.produces == ["mcp_servers"]
        assert len(check.conditions) == 2
        assert {c.output_name for c in check.conditions} == {"services", "services_probed"}

    @pytest.mark.asyncio
    async def test_discovers_mcp_via_well_known(self, check, sample_service):
        """Test MCP discovery via .well-known path with JSON-RPC initialize response."""
        mock_client = AsyncMock()

        # Realistic initialize response with capabilities and serverInfo
        initialize_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": True},
                    },
                    "serverInfo": {"name": "acme-mcp", "version": "0.9.3"},
                },
            }
        )

        async def mock_get(url, **kwargs):
            if "/.well-known/mcp" in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "application/json; charset=utf-8",
                        "x-mcp-version": "2024-11-05",
                        "server": "nginx/1.25.3",
                        "x-request-id": "abc-def-123",
                        "cache-control": "no-store",
                    },
                    body=initialize_body,
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success

        # Exactly one server discovered
        servers = result.outputs["mcp_servers"]
        assert len(servers) == 1
        server = servers[0]
        assert server["path"] == "/.well-known/mcp"
        assert server["transport"] == "http"
        assert "tools" in server["capabilities"]
        assert "resources" in server["capabilities"]
        assert server["auth_required"] is False
        assert server["server_info"]["name"] == "acme-mcp"

        # Exactly one observation with specific fields
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "MCP server discovered: /.well-known/mcp"
        assert obs.severity == "medium"  # Has capabilities -> medium
        assert "x-mcp-version" in obs.evidence
        assert "/.well-known/mcp" in obs.evidence

    @pytest.mark.asyncio
    async def test_detects_mcp_session_header(self, check, sample_service):
        """Test detection via mcp-session-id header among irrelevant headers."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # Only match the exact /mcp path (port 8080), not /.well-known/mcp
            if url == "http://mcp.example.com:8080/mcp":
                return make_response(
                    status_code=200,
                    headers={
                        "mcp-session-id": "sess-7f3a9c",
                        "content-type": "application/json",
                        "x-powered-by": "Express",
                        "vary": "Accept-Encoding",
                        "etag": 'W/"2a-abc"',
                        "x-request-id": "req-99887766",
                    },
                    body='{"status": "ok"}',
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        servers = result.outputs["mcp_servers"]
        assert len(servers) == 1
        assert servers[0]["path"] == "/mcp"

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "MCP server discovered: /mcp"
        # No capabilities extracted -> severity is info
        assert obs.severity == "info"
        assert "mcp-session-id" in obs.evidence

    @pytest.mark.asyncio
    async def test_detects_sse_transport(self, check, sample_service):
        """Test SSE transport detection on /mcp/sse path."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/mcp/sse" in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "text/event-stream",
                        "cache-control": "no-cache",
                        "connection": "keep-alive",
                        "x-accel-buffering": "no",
                    },
                    body="",
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        servers = result.outputs["mcp_servers"]
        assert len(servers) == 1
        assert servers[0]["transport"] == "sse"
        assert servers[0]["path"] == "/mcp/sse"

        obs = result.observations[0]
        assert obs.title == "MCP server discovered: /mcp/sse"

    @pytest.mark.asyncio
    async def test_detects_auth_required(self, check, sample_service):
        """Test auth requirement detection via 401 on an MCP path."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # The check probes paths in order; /.well-known/mcp is first.
            # Return 401 on it to trigger auth_required detection.
            if "/.well-known/mcp" in url:
                return make_response(
                    status_code=401,
                    headers={
                        "www-authenticate": "Bearer",
                        "content-type": "application/json",
                    },
                    body='{"error": "unauthorized"}',
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        servers = result.outputs["mcp_servers"]
        assert len(servers) == 1
        assert servers[0]["auth_required"] is True

        obs = result.observations[0]
        assert obs.title == "MCP server discovered: /.well-known/mcp"
        assert "auth-required" in obs.evidence

    @pytest.mark.asyncio
    async def test_no_mcp_found_all_404(self, check, sample_service):
        """Test when no MCP endpoints found (all paths return 404)."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        assert result.outputs.get("mcp_servers") is None
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_negative_json_on_mcp_path_without_mcp_indicators(self, check, sample_service):
        """Negative: JSON response on /mcp without any MCP headers, body patterns, or keywords.

        A generic REST API that happens to live at /mcp should NOT be detected
        as an MCP server.
        """
        mock_client = AsyncMock()

        # Return a generic JSON API response with no MCP indicators
        generic_body = json.dumps(
            {
                "version": "2.1.0",
                "uptime": 86400,
                "endpoints": ["/health", "/metrics"],
            }
        )

        async def mock_get(url, **kwargs):
            if "/mcp" in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "application/json",
                        "server": "gunicorn/21.2.0",
                        "x-request-id": "req-001",
                    },
                    body=generic_body,
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        # No MCP indicators -> no servers discovered
        assert result.outputs.get("mcp_servers") is None
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_negative_non_mcp_sse_endpoint(self, check, sample_service):
        """Negative: A non-MCP SSE endpoint at a non-MCP path should not trigger detection
        unless it is on a probed path. Since /events IS a probed path, use a scenario where
        the SSE endpoint returns event-stream but we verify it IS detected (SSE on probed path
        is a valid indicator). Instead, test that a 200 HTML page on /sse does not trigger."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # All probed paths return 404, except /sse which returns HTML (not event-stream)
            if url.endswith("/sse"):
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "text/html; charset=utf-8",
                        "server": "Apache/2.4",
                    },
                    body="<html><body>Server Sent Events Dashboard</body></html>",
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.discovery.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, {"services": [sample_service]})

        assert result.success
        # HTML page with no MCP indicators should not produce any servers
        assert result.outputs.get("mcp_servers") is None
        assert len(result.observations) == 0


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
        assert check.produces == ["mcp_tools", "high_risk_tools"]
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "mcp_servers"

    @pytest.mark.asyncio
    async def test_enumerates_tools_jsonrpc(self, check, sample_service, mcp_server_context):
        """Test tool enumeration via JSON-RPC with realistic response."""
        mock_client = AsyncMock()

        tools_response = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Echo back the input string",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"message": {"type": "string"}},
                            },
                        },
                        {
                            "name": "ping",
                            "description": "Simple health check that returns pong",
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                            },
                        },
                    ]
                },
            }
        )

        mock_client.post = AsyncMock(
            return_value=make_response(status_code=200, body=tools_response)
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.tool_enumeration.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, mcp_server_context)

        assert result.success
        tools = result.outputs["mcp_tools"]
        assert len(tools) == 2
        tool_names = {t["name"] for t in tools}
        assert tool_names == {"echo", "ping"}

        # Both are benign -> no high risk tools
        assert result.outputs.get("high_risk_tools") is None

        # Two observations, one per tool, both info severity
        assert len(result.observations) == 2
        for obs in result.observations:
            assert obs.severity == "info"
            assert "info risk" in obs.title

    @pytest.mark.asyncio
    async def test_classifies_critical_tools(self, check, sample_service, mcp_server_context):
        """Test critical tool detection (exec, eval) with specific assertions."""
        mock_client = AsyncMock()

        tools_response = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": "execute_command",
                            "description": "Execute a shell command on the server",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "command": {"type": "string"},
                                    "timeout": {"type": "integer"},
                                },
                                "required": ["command"],
                            },
                        },
                        {
                            "name": "eval_code",
                            "description": "Evaluate Python code in a sandbox",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"code": {"type": "string"}},
                                "required": ["code"],
                            },
                        },
                    ]
                },
            }
        )

        mock_client.post = AsyncMock(
            return_value=make_response(status_code=200, body=tools_response)
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.tool_enumeration.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, mcp_server_context)

        assert result.success

        # Both tools should be high-risk (critical level)
        high_risk = result.outputs["high_risk_tools"]
        assert len(high_risk) == 2
        hr_names = {t["name"] for t in high_risk}
        assert hr_names == {"execute_command", "eval_code"}
        for t in high_risk:
            assert t["risk_level"] == "critical"

        # Two observations, both critical severity
        assert len(result.observations) == 2
        for obs in result.observations:
            assert obs.severity == "critical"

        # Check specific titles
        titles = {obs.title for obs in result.observations}
        assert "MCP tool: execute_command (critical risk)" in titles
        assert "MCP tool: eval_code (critical risk)" in titles

        # Evidence should contain tool names and risk indicators
        exec_obs = next(o for o in result.observations if "execute_command" in o.title)
        assert "execute_command" in exec_obs.evidence
        assert "critical" in exec_obs.evidence.lower()

    @pytest.mark.asyncio
    async def test_classifies_high_risk_tools(self, check, sample_service, mcp_server_context):
        """Test high-risk tool detection (file, http, sql) with specific assertions."""
        mock_client = AsyncMock()

        tools_response = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Read contents of a file from disk",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                            },
                        },
                        {
                            "name": "write_file",
                            "description": "Write content to a file on disk",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                    "content": {"type": "string"},
                                },
                            },
                        },
                        {
                            "name": "http_request",
                            "description": "Make an outbound HTTP request",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "url": {"type": "string"},
                                    "method": {"type": "string"},
                                },
                            },
                        },
                    ]
                },
            }
        )

        mock_client.post = AsyncMock(
            return_value=make_response(status_code=200, body=tools_response)
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.tool_enumeration.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, mcp_server_context)

        assert result.success

        # All three are high-risk
        high_risk = result.outputs["high_risk_tools"]
        assert len(high_risk) == 3
        hr_names = {t["name"] for t in high_risk}
        assert hr_names == {"read_file", "write_file", "http_request"}
        for t in high_risk:
            assert t["risk_level"] == "high"

        # Three observations, all high severity
        assert len(result.observations) == 3
        titles = {obs.title for obs in result.observations}
        assert "MCP tool: read_file (high risk)" in titles
        assert "MCP tool: write_file (high risk)" in titles
        assert "MCP tool: http_request (high risk)" in titles

        for obs in result.observations:
            assert obs.severity == "high"

    @pytest.mark.asyncio
    async def test_benign_tools_info_severity(self, check, sample_service, mcp_server_context):
        """Test benign tools get info severity and are not in high_risk_tools."""
        mock_client = AsyncMock()

        tools_response = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Echo back the provided text",
                        },
                        {
                            "name": "ping",
                            "description": "Return a simple pong response",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "payload": {"type": "string"},
                                },
                            },
                        },
                    ]
                },
            }
        )

        mock_client.post = AsyncMock(
            return_value=make_response(status_code=200, body=tools_response)
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.tool_enumeration.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, mcp_server_context)

        assert result.success

        # No high risk tools
        assert result.outputs.get("high_risk_tools") is None

        # Two tools enumerated
        tools = result.outputs["mcp_tools"]
        assert len(tools) == 2
        for t in tools:
            assert t["risk_level"] == "info"

        # Observations are info severity
        assert len(result.observations) == 2
        for obs in result.observations:
            assert obs.severity == "info"
            assert "info risk" in obs.title

    @pytest.mark.asyncio
    async def test_mixed_risk_tools(self, check, sample_service, mcp_server_context):
        """Test a mix of critical, high, and benign tools are classified correctly."""
        mock_client = AsyncMock()

        tools_response = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [
                        {"name": "execute_command", "description": "Run a shell command"},
                        {"name": "read_file", "description": "Read file from disk"},
                        {"name": "echo", "description": "Echo back input text"},
                    ]
                },
            }
        )

        mock_client.post = AsyncMock(
            return_value=make_response(status_code=200, body=tools_response)
        )
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()

        with patch("app.checks.mcp.tool_enumeration.AsyncHttpClient", return_value=mock_client):
            result = await check.check_service(sample_service, mcp_server_context)

        assert result.success

        # Only critical and high go into high_risk_tools
        high_risk = result.outputs["high_risk_tools"]
        assert len(high_risk) == 2
        hr_names = {t["name"] for t in high_risk}
        assert hr_names == {"execute_command", "read_file"}

        # All three tools enumerated
        all_tools = result.outputs["mcp_tools"]
        assert len(all_tools) == 3

        # Verify per-tool severities via observations
        obs_by_title = {o.title: o for o in result.observations}
        assert obs_by_title["MCP tool: execute_command (critical risk)"].severity == "critical"
        assert obs_by_title["MCP tool: read_file (high risk)"].severity == "high"
        assert obs_by_title["MCP tool: echo (info risk)"].severity == "info"

    @pytest.mark.asyncio
    async def test_no_mcp_servers_skips(self, check, sample_service):
        """Test check skips when no MCP servers in context."""
        result = await check.check_service(sample_service, {})

        assert result.success
        assert len(result.observations) == 0
        assert result.outputs.get("mcp_tools") is None
        assert result.outputs.get("high_risk_tools") is None
