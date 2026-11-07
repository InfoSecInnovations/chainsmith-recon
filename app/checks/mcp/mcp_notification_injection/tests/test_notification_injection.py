"""Tests for mcp_notification_injection."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_notification_injection import MCPNotificationInjectionCheck
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
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


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

        with patch(
            "app.checks.mcp.mcp_notification_injection.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

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

        with patch(
            "app.checks.mcp.mcp_notification_injection.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

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

        with patch(
            "app.checks.mcp.mcp_notification_injection.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "rejects" in info[0].title.lower()
        serious = [f for f in result.observations if f.severity in ("medium", "high", "critical")]
        assert len(serious) == 0
