"""Tests for mcp_transport_security."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_transport_security import TransportSecurityCheck
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


class TestTransportSecurityCheck:
    @pytest.fixture
    def check(self):
        return TransportSecurityCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_transport_security"

    @pytest.mark.asyncio
    async def test_plain_http_flagged(self, check, http_mcp_context):
        """HTTP-scheme MCP server produces a high-severity 'plain HTTP' finding."""
        mock = mock_client_factory()
        mock.options = AsyncMock(return_value=make_response(status_code=404))
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch(
            "app.checks.mcp.mcp_transport_security.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, http_mcp_context)

        assert result.success
        # Find the exact observation by title
        plain_http = [
            f for f in result.observations if f.title == "MCP served over plain HTTP (no TLS)"
        ]
        assert len(plain_http) == 1
        assert plain_http[0].severity == "high"
        assert "http://mcp.example.com:8080/mcp" in plain_http[0].evidence

    @pytest.mark.asyncio
    async def test_https_server_no_plain_http_finding(self, check, https_mcp_context):
        """HTTPS-scheme MCP server must NOT produce a 'plain HTTP' finding."""
        mock = mock_client_factory()
        mock.options = AsyncMock(return_value=make_response(status_code=404))
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch(
            "app.checks.mcp.mcp_transport_security.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, https_mcp_context)

        assert result.success
        plain_http = [
            f
            for f in result.observations
            if "plain http" in f.title.lower() or "no tls" in f.title.lower()
        ]
        assert len(plain_http) == 0

        # Instead, with no issues found, we should get the "adequate" observation
        adequate = [f for f in result.observations if "adequate" in f.title.lower()]
        assert len(adequate) == 1
        assert adequate[0].severity == "info"

    @pytest.mark.asyncio
    async def test_cors_wildcard(self, check, http_mcp_context):
        """CORS wildcard (*) produces a high-severity finding with exact title."""
        mock = mock_client_factory()
        mock.options = AsyncMock(
            return_value=make_response(headers={"Access-Control-Allow-Origin": "*"})
        )
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch(
            "app.checks.mcp.mcp_transport_security.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, http_mcp_context)

        cors = [
            f
            for f in result.observations
            if f.title == "MCP endpoint allows cross-origin requests from any origin (CORS: *)"
        ]
        assert len(cors) == 1
        assert cors[0].severity == "high"
        assert "Access-Control-Allow-Origin: *" in cors[0].evidence

    @pytest.mark.asyncio
    async def test_cors_reflects_origin(self, check, http_mcp_context):
        """CORS reflecting arbitrary origin produces a high-severity finding."""
        mock = mock_client_factory()
        mock.options = AsyncMock(
            return_value=make_response(
                headers={"Access-Control-Allow-Origin": "https://evil.attacker.com"}
            )
        )
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch(
            "app.checks.mcp.mcp_transport_security.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, http_mcp_context)

        reflects = [
            f
            for f in result.observations
            if f.title == "MCP endpoint reflects arbitrary Origin in CORS response"
        ]
        assert len(reflects) == 1
        assert reflects[0].severity == "high"
        assert "evil.attacker.com" in reflects[0].evidence
