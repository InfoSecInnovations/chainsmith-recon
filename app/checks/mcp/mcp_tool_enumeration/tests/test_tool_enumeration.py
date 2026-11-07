"""Tests for mcp_tool_enumeration."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_tool_enumeration import MCPToolEnumerationCheck
from app.lib.http import HttpResponse


async def probe_and_grade(check, service, context):
    """Run the probe, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.check_service(service, context)
    return await grade_result(check, result, context)


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
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.checks.mcp.mcp_tool_enumeration.check.AsyncHttpClient", return_value=mock_client
        ):
            result = await probe_and_grade(check, sample_service, mcp_server_context)

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
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.checks.mcp.mcp_tool_enumeration.check.AsyncHttpClient", return_value=mock_client
        ):
            result = await probe_and_grade(check, sample_service, mcp_server_context)

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
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.checks.mcp.mcp_tool_enumeration.check.AsyncHttpClient", return_value=mock_client
        ):
            result = await probe_and_grade(check, sample_service, mcp_server_context)

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
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.checks.mcp.mcp_tool_enumeration.check.AsyncHttpClient", return_value=mock_client
        ):
            result = await probe_and_grade(check, sample_service, mcp_server_context)

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
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "app.checks.mcp.mcp_tool_enumeration.check.AsyncHttpClient", return_value=mock_client
        ):
            result = await probe_and_grade(check, sample_service, mcp_server_context)

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
        result = await probe_and_grade(check, sample_service, {})

        assert result.success
        assert len(result.observations) == 0
        assert result.outputs.get("mcp_tools") is None
        assert result.outputs.get("high_risk_tools") is None
