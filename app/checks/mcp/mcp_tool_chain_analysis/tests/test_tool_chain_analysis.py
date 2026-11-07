"""Tests for mcp_tool_chain_analysis."""

from unittest.mock import AsyncMock

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_tool_chain_analysis import ToolChainAnalysisCheck
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
        result = await run_and_grade(check, mcp_tools_context)
        assert result.success
        assert "mcp_dangerous_chains" in result.outputs
        chains = result.outputs["mcp_dangerous_chains"]
        exfil_chain = [
            c
            for c in chains
            if "exfil" in c["chain_name"].lower() or "data read" in c["chain_name"].lower()
        ]
        assert len(exfil_chain) >= 1
        assert exfil_chain[0]["severity"] == "critical"
        assert "read_file" in exfil_chain[0]["source_tools"]

    @pytest.mark.asyncio
    async def test_detects_rce_chain(self, check, mcp_tools_context):
        """read_file + execute_command = file access + code exec chain."""
        result = await run_and_grade(check, mcp_tools_context)
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) >= 1
        chain_titles = [f.title for f in critical]
        assert any("File Access + Code Execution" in t for t in chain_titles)

    @pytest.mark.asyncio
    async def test_no_chains_for_benign_tools(self, check):
        """Benign tools (no dangerous capabilities) produce no chain observations."""
        ctx = {
            "mcp_tools": [
                {"name": "get_time", "description": "Get time", "service_host": "test"},
                {"name": "format_text", "description": "Format text", "service_host": "test"},
            ]
        }
        result = await run_and_grade(check, ctx)
        assert result.success
        # Should get the "no dangerous chains" info observation
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert info[0].title == "No dangerous tool chain categories detected"
        # No critical or high findings
        assert not [f for f in result.observations if f.severity in ("critical", "high")]
