"""Tests for mcp_server_fingerprint."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_server_fingerprint import MCPServerFingerprintCheck
from app.lib.http import HttpResponse


async def run_and_grade(check, context):
    """Run the check, then the grading stage, and return the graded result."""
    from app.grading import grade_result

    result = await check.run(context)
    return await grade_result(check, result, context)


@pytest.fixture
def http_service():
    return Service(
        url="http://mcp.example.com:8080",
        host="mcp.example.com",
        port=8080,
        scheme="http",
        service_type="ai",
    )


@pytest.fixture
def https_service():
    return Service(
        url="https://mcp.example.com:443",
        host="mcp.example.com",
        port=443,
        scheme="https",
        service_type="ai",
    )


@pytest.fixture
def http_mcp_context(http_service):
    return {
        "mcp_servers": [
            {
                "url": "http://mcp.example.com:8080/mcp",
                "path": "/mcp",
                "transport": "http",
                "capabilities": ["tools", "resources"],
                "auth_required": False,
                "server_info": {"name": "test-server", "version": "1.0"},
                "service": http_service.to_dict(),
            }
        ]
    }


@pytest.fixture
def https_mcp_context(https_service):
    return {
        "mcp_servers": [
            {
                "url": "https://mcp.example.com:443/mcp",
                "path": "/mcp",
                "transport": "http",
                "capabilities": ["tools", "resources"],
                "auth_required": False,
                "server_info": {"name": "test-server", "version": "1.0"},
                "service": https_service.to_dict(),
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
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


class TestMCPServerFingerprintCheck:
    @pytest.fixture
    def check(self):
        return MCPServerFingerprintCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_server_fingerprint"

    @pytest.mark.asyncio
    async def test_fingerprint_from_server_info(self, check, http_mcp_context):
        """Server with name 'test-server' gets identified via raw name match (medium confidence)."""
        mock = mock_client_factory()
        # Error probe returns a generic 404 with no fingerprint-matching body
        mock.post = AsyncMock(return_value=make_response(status_code=404))

        with patch(
            "app.checks.mcp.mcp_server_fingerprint.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, http_mcp_context)

        assert result.success

        # Verify implementations output contains correct structure
        impls = result.outputs["mcp_server_implementations"]
        assert len(impls) == 1
        impl = impls[0]
        assert impl["identified"] is True
        assert impl["implementation"] == "test-server"
        assert impl["version"] == "1.0"
        assert impl["confidence"] == "medium"
        assert impl["match_method"] == "server_name_raw"

        # Verify the observation
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "MCP server identified: test-server v1.0"
        assert obs.severity == "info"
        assert "test-server" in obs.evidence
        assert "medium" in obs.evidence

    @pytest.mark.asyncio
    async def test_fingerprint_known_sdk_match(self, check):
        """Server with name matching a known SDK signature gets high confidence."""
        svc = Service(
            url="http://test:8080",
            host="test",
            port=8080,
            scheme="http",
            service_type="ai",
        )
        ctx = {
            "mcp_servers": [
                {
                    "url": "http://test:8080/mcp",
                    "path": "/mcp",
                    "transport": "http",
                    "capabilities": ["tools", "resources", "prompts"],
                    "auth_required": False,
                    "server_info": {
                        "name": "@modelcontextprotocol/sdk",
                        "version": "0.9.1",
                    },
                    "service": svc.to_dict(),
                }
            ]
        }
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=404))

        with patch(
            "app.checks.mcp.mcp_server_fingerprint.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, ctx)

        assert result.success
        impls = result.outputs["mcp_server_implementations"]
        assert len(impls) == 1
        assert impls[0]["implementation"] == "Official TypeScript SDK"
        assert impls[0]["version"] == "0.9.1"
        assert impls[0]["confidence"] == "high"
        assert impls[0]["match_method"] == "server_name"

        obs = result.observations[0]
        assert "Official TypeScript SDK" in obs.title
        assert obs.severity == "info"

    @pytest.mark.asyncio
    async def test_fingerprint_from_error_mcperror(self, check):
        """McpError in error body triggers Python SDK fingerprint via error_format."""
        svc = Service(
            url="http://test:8080",
            host="test",
            port=8080,
            scheme="http",
            service_type="ai",
        )
        ctx = {
            "mcp_servers": [
                {
                    "url": "http://test:8080/mcp",
                    "path": "/mcp",
                    "transport": "http",
                    "capabilities": [],
                    "auth_required": False,
                    "server_info": {},
                    "service": svc.to_dict(),
                }
            ]
        }
        mock = mock_client_factory()
        # Realistic JSON-RPC error response with McpError pattern
        mock.post = AsyncMock(
            return_value=make_response(
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32601,
                            "message": "McpError: method not found",
                            "data": {"method": "nonexistent/method_that_does_not_exist"},
                        },
                        "id": 999,
                    }
                )
            )
        )

        with patch(
            "app.checks.mcp.mcp_server_fingerprint.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, ctx)

        assert result.success
        impls = result.outputs["mcp_server_implementations"]
        assert len(impls) == 1
        assert impls[0]["identified"] is True
        assert impls[0]["implementation"] == "Official Python SDK (mcp)"
        assert impls[0]["confidence"] == "medium"
        assert impls[0]["match_method"] == "error_format"

    @pytest.mark.asyncio
    async def test_no_fingerprint_from_generic_error(self, check):
        """A non-MCP generic error body should NOT match any known implementation."""
        svc = Service(
            url="http://test:8080",
            host="test",
            port=8080,
            scheme="http",
            service_type="ai",
        )
        ctx = {
            "mcp_servers": [
                {
                    "url": "http://test:8080/mcp",
                    "path": "/mcp",
                    "transport": "http",
                    "capabilities": [],
                    "auth_required": False,
                    "server_info": {},
                    "service": svc.to_dict(),
                }
            ]
        }
        mock = mock_client_factory()
        # Generic HTTP error response that doesn't match any MCP SDK patterns
        mock.post = AsyncMock(
            return_value=make_response(
                status_code=400,
                body=json.dumps(
                    {
                        "status": "error",
                        "message": "Bad request: invalid JSON payload",
                        "code": 400,
                    }
                ),
            )
        )

        with patch(
            "app.checks.mcp.mcp_server_fingerprint.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, ctx)

        assert result.success
        impls = result.outputs["mcp_server_implementations"]
        assert len(impls) == 1
        assert impls[0]["identified"] is False
        assert impls[0]["implementation"] == "Unknown/Custom"
        assert impls[0]["confidence"] == "low"

        # Should get the "custom implementation" observation
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "MCP server is custom implementation (non-standard)"
        assert obs.severity == "low"
