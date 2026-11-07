"""Tests for mcp_websocket_transport."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_websocket_transport import WebSocketTransportCheck
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


def make_response(status_code=200, headers=None, body="", error=None, url="http://test"):
    return HttpResponse(
        url=url,
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
                return make_response(status_code=101, url=url)
            return make_response(status_code=404, url=url)

        mock.get = mock_get

        with patch(
            "app.checks.mcp.mcp_websocket_transport.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

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

        with patch(
            "app.checks.mcp.mcp_websocket_transport.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

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
                return make_response(status_code=101, url=url)
            return make_response(status_code=404, url=url)

        mock.get = mock_get

        with patch(
            "app.checks.mcp.mcp_websocket_transport.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context_auth_required)

        high = [f for f in result.observations if f.severity == "high"]
        assert len(high) == 1
        assert "no authentication" in high[0].title.lower()
        assert "http endpoint requires auth" in high[0].title.lower()
        assert "101" in high[0].evidence
