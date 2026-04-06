"""Tests for MCP discovery checks: server fingerprinting, protocol version, transport security."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.protocol_version import MCPProtocolVersionCheck
from app.checks.mcp.server_fingerprint import MCPServerFingerprintCheck
from app.checks.mcp.transport_security import TransportSecurityCheck
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
# MCPServerFingerprintCheck
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
        svc = Service(
            url="http://test:8080", host="test", port=8080, scheme="http", service_type="ai"
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
        mock.post = AsyncMock(
            return_value=make_response(
                body='{"error": "McpError: method not found", "code": -32601}'
            )
        )

        with patch("app.checks.mcp.server_fingerprint.AsyncHttpClient", return_value=mock):
            result = await check.run(ctx)

        assert result.success


# ═══════════════════════════════════════════════════════════════════════════════
# MCPProtocolVersionCheck
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
            return make_response(
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "result": {
                            "protocolVersion": version,
                            "capabilities": {"tools": {}} if version >= "2024-11-05" else {},
                        },
                    }
                )
            )

        mock.post = mock_post

        with patch("app.checks.mcp.protocol_version.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        assert result.success
        assert "mcp_protocol_versions" in result.outputs
        downgrade = [f for f in result.findings if "downgrade" in f.title.lower()]
        assert len(downgrade) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# TransportSecurityCheck
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
        mock.options = AsyncMock(
            return_value=make_response(headers={"Access-Control-Allow-Origin": "*"})
        )
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.transport_security.AsyncHttpClient", return_value=mock):
            result = await check.run(mcp_server_context)

        cors = [f for f in result.findings if "cors" in f.title.lower()]
        assert len(cors) > 0
