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
    async def test_fingerprint_from_server_info(self, check, http_mcp_context):
        """Server with name 'test-server' gets identified via raw name match (medium confidence)."""
        mock = mock_client_factory()
        # Error probe returns a generic 404 with no fingerprint-matching body
        mock.post = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.server_fingerprint.AsyncHttpClient", return_value=mock):
            result = await check.run(http_mcp_context)

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

        with patch("app.checks.mcp.server_fingerprint.AsyncHttpClient", return_value=mock):
            result = await check.run(ctx)

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

        with patch("app.checks.mcp.server_fingerprint.AsyncHttpClient", return_value=mock):
            result = await check.run(ctx)

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

        with patch("app.checks.mcp.server_fingerprint.AsyncHttpClient", return_value=mock):
            result = await check.run(ctx)

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
    async def test_downgrade_detected(self, check, http_mcp_context):
        """Server that accepts all versions with different caps triggers downgrade finding."""
        mock = mock_client_factory()

        # The server responds with a fixed server version (the latest it supports),
        # but varies capabilities depending on the requested version.
        # This is realistic: real servers negotiate and return their own version,
        # not an echo of the client's requested version.
        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            version = body.get("params", {}).get("protocolVersion", "")
            # Server always responds with its own version and serverInfo
            # but adjusts capabilities based on what the requested version supports
            if version >= "2024-11-05":
                caps = {"tools": {"listChanged": True}, "resources": {"subscribe": True}}
            else:
                # Older versions get fewer capabilities
                caps = {}
            return make_response(
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": caps,
                            "serverInfo": {"name": "test-mcp", "version": "2.1.0"},
                        },
                    }
                )
            )

        mock.post = mock_post

        with patch("app.checks.mcp.protocol_version.AsyncHttpClient", return_value=mock):
            result = await check.run(http_mcp_context)

        assert result.success
        versions = result.outputs["mcp_protocol_versions"]
        assert len(versions) == 1
        assert len(versions[0]["accepted"]) == 5  # all 5 protocol versions accepted

        # There should be a downgrade observation with medium severity (caps differ)
        downgrade = [f for f in result.observations if "downgrade" in f.title.lower()]
        assert len(downgrade) == 1
        obs = downgrade[0]
        assert obs.severity == "medium"
        assert "2024-01-01" in obs.title  # oldest accepted version in title
        assert "tools" in obs.evidence or "resources" in obs.evidence

    @pytest.mark.asyncio
    async def test_downgrade_low_severity_when_caps_same(self, check, http_mcp_context):
        """Downgrade with identical capabilities across versions gets low severity."""
        mock = mock_client_factory()

        async def mock_post(url, **kwargs):
            return make_response(
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "test-mcp", "version": "1.0"},
                        },
                    }
                )
            )

        mock.post = mock_post

        with patch("app.checks.mcp.protocol_version.AsyncHttpClient", return_value=mock):
            result = await check.run(http_mcp_context)

        assert result.success
        downgrade = [f for f in result.observations if "downgrade" in f.title.lower()]
        assert len(downgrade) == 1
        assert downgrade[0].severity == "low"


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
    async def test_plain_http_flagged(self, check, http_mcp_context):
        """HTTP-scheme MCP server produces a high-severity 'plain HTTP' finding."""
        mock = mock_client_factory()
        mock.options = AsyncMock(return_value=make_response(status_code=404))
        mock.post = AsyncMock(return_value=make_response(status_code=401))
        mock.get = AsyncMock(return_value=make_response(status_code=404))

        with patch("app.checks.mcp.transport_security.AsyncHttpClient", return_value=mock):
            result = await check.run(http_mcp_context)

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

        with patch("app.checks.mcp.transport_security.AsyncHttpClient", return_value=mock):
            result = await check.run(https_mcp_context)

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

        with patch("app.checks.mcp.transport_security.AsyncHttpClient", return_value=mock):
            result = await check.run(http_mcp_context)

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

        with patch("app.checks.mcp.transport_security.AsyncHttpClient", return_value=mock):
            result = await check.run(http_mcp_context)

        reflects = [
            f
            for f in result.observations
            if f.title == "MCP endpoint reflects arbitrary Origin in CORS response"
        ]
        assert len(reflects) == 1
        assert reflects[0].severity == "high"
        assert "evil.attacker.com" in reflects[0].evidence
