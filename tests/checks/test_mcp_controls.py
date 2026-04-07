"""Tests for MCP control checks: rate limiting, capability validation, invocation safety, chain analysis, shadow tools."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.invocation_safety import (
    build_probe_payload,
    build_safe_payload,
    cap_response,
    classify_tool_probe_type,
    is_payload_safe,
)
from app.checks.mcp.rate_limit import ToolRateLimitCheck
from app.checks.mcp.shadow_tool_detection import ShadowToolDetectionCheck
from app.checks.mcp.tool_chain_analysis import ToolChainAnalysisCheck
from app.checks.mcp.tool_invocation import MCPToolInvocationCheck
from app.checks.mcp.undeclared_capabilities import UndeclaredCapabilityCheck
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
# ToolChainAnalysisCheck
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
        assert any(
            "exfil" in c["chain_name"].lower() or "read" in c["chain_name"].lower() for c in chains
        )

    @pytest.mark.asyncio
    async def test_detects_rce_chain(self, check, mcp_tools_context):
        """read_file + execute_command = file access + code exec."""
        result = await check.run(mcp_tools_context)
        critical = [f for f in result.observations if f.severity == "critical"]
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
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# ShadowToolDetectionCheck
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
        flat_observations = [f for f in result.observations if "flat" in f.title.lower()]
        assert len(flat_observations) > 0

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
        info = [f for f in result.observations if f.severity == "info"]
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

        high = [f for f in result.observations if f.severity == "high"]
        assert any(
            "list_changed" in f.title.lower() or "re-registration" in f.title.lower() for f in high
        )


# ═══════════════════════════════════════════════════════════════════════════════
# MCPToolInvocationCheck
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
        exec_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "result": {"content": [{"type": "text", "text": "chainsmith-probe\nroot"}]},
            }
        )
        mock.post = AsyncMock(return_value=make_response(body=exec_body))

        with patch("app.checks.mcp.tool_invocation.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_tools_context)

        assert result.success
        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_auth_required_tool(self, check, mcp_tools_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=403))

        with patch("app.checks.mcp.tool_invocation.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_tools_context)

        assert result.success
        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# ToolRateLimitCheck
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
        mock.post = AsyncMock(
            return_value=make_response(
                body=json.dumps({"jsonrpc": "2.0", "result": {"content": [{"text": "ok"}]}})
            )
        )

        with patch("app.checks.mcp.rate_limit.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_tools_context)

        assert result.success
        medium = [f for f in result.observations if f.severity == "medium"]
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
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# UndeclaredCapabilityCheck
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
                return make_response(
                    body=json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "result": {"tools": [{"name": "hidden_tool"}]},
                        }
                    )
                )
            return make_response(body=json.dumps({"jsonrpc": "2.0", "error": {"code": -32601}}))

        mock.post = mock_post

        with patch("app.checks.mcp.undeclared_capabilities.AsyncHttpClient", return_value=mock):
            result = await check.run(ctx)

        assert result.success
        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) > 0

    @pytest.mark.asyncio
    async def test_all_rejected(self, check, mcp_server_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(
            return_value=make_response(
                body=json.dumps(
                    {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Not found"}}
                )
            )
        )

        with patch("app.checks.mcp.undeclared_capabilities.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
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
            "input_schema": {
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
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
