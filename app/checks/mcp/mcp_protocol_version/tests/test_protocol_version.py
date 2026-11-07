"""Tests for mcp_protocol_version."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_protocol_version import MCPProtocolVersionCheck
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

        with patch("app.checks.mcp.mcp_protocol_version.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, http_mcp_context)

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

        with patch("app.checks.mcp.mcp_protocol_version.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, http_mcp_context)

        assert result.success
        downgrade = [f for f in result.observations if "downgrade" in f.title.lower()]
        assert len(downgrade) == 1
        assert downgrade[0].severity == "low"
