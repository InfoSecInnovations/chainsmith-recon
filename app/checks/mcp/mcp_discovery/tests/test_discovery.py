"""Tests for mcp_discovery."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_discovery import MCPDiscoveryCheck
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


class TestMCPDiscoveryCheck:
    """Tests for MCPDiscoveryCheck."""

    @pytest.fixture
    def check(self):
        return MCPDiscoveryCheck()

    def test_check_metadata(self, check):
        """Test check has required metadata."""
        assert check.name == "mcp_discovery"
        assert check.produces == ["mcp_servers"]
        assert len(check.conditions) == 2
        assert {c.output_name for c in check.conditions} == {"services", "services_probed"}

    @pytest.mark.asyncio
    async def test_discovers_mcp_via_well_known(self, check, sample_service):
        """Test MCP discovery via .well-known path with JSON-RPC initialize response."""
        mock_client = AsyncMock()

        # Realistic initialize response with capabilities and serverInfo
        initialize_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": True},
                    },
                    "serverInfo": {"name": "acme-mcp", "version": "0.9.3"},
                },
            }
        )

        async def mock_get(url, **kwargs):
            if "/.well-known/mcp" in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "application/json; charset=utf-8",
                        "x-mcp-version": "2024-11-05",
                        "server": "nginx/1.25.3",
                        "x-request-id": "abc-def-123",
                        "cache-control": "no-store",
                    },
                    body=initialize_body,
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.mcp.mcp_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success

        # Exactly one server discovered
        servers = result.outputs["mcp_servers"]
        assert len(servers) == 1
        server = servers[0]
        assert server["path"] == "/.well-known/mcp"
        assert server["transport"] == "http"
        assert "tools" in server["capabilities"]
        assert "resources" in server["capabilities"]
        assert server["auth_required"] is False
        assert server["server_info"]["name"] == "acme-mcp"

        # Exactly one observation with specific fields
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "MCP server discovered: /.well-known/mcp"
        assert obs.severity == "medium"  # Has capabilities -> medium
        assert "x-mcp-version" in obs.evidence
        assert "/.well-known/mcp" in obs.evidence

    @pytest.mark.asyncio
    async def test_detects_mcp_session_header(self, check, sample_service):
        """Test detection via mcp-session-id header among irrelevant headers."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # Only match the exact /mcp path (port 8080), not /.well-known/mcp
            if url == "http://mcp.example.com:8080/mcp":
                return make_response(
                    status_code=200,
                    headers={
                        "mcp-session-id": "sess-7f3a9c",
                        "content-type": "application/json",
                        "x-powered-by": "Express",
                        "vary": "Accept-Encoding",
                        "etag": 'W/"2a-abc"',
                        "x-request-id": "req-99887766",
                    },
                    body='{"status": "ok"}',
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.mcp.mcp_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        servers = result.outputs["mcp_servers"]
        assert len(servers) == 1
        assert servers[0]["path"] == "/mcp"

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == "MCP server discovered: /mcp"
        # No capabilities extracted -> severity is info
        assert obs.severity == "info"
        assert "mcp-session-id" in obs.evidence

    @pytest.mark.asyncio
    async def test_detects_sse_transport(self, check, sample_service):
        """Test SSE transport detection on /mcp/sse path."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            if "/mcp/sse" in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "text/event-stream",
                        "cache-control": "no-cache",
                        "connection": "keep-alive",
                        "x-accel-buffering": "no",
                    },
                    body="",
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.mcp.mcp_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        servers = result.outputs["mcp_servers"]
        assert len(servers) == 1
        assert servers[0]["transport"] == "sse"
        assert servers[0]["path"] == "/mcp/sse"

        obs = result.observations[0]
        assert obs.title == "MCP server discovered: /mcp/sse"

    @pytest.mark.asyncio
    async def test_detects_auth_required(self, check, sample_service):
        """Test auth requirement detection via 401 on an MCP path."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # The check probes paths in order; /.well-known/mcp is first.
            # Return 401 on it to trigger auth_required detection.
            if "/.well-known/mcp" in url:
                return make_response(
                    status_code=401,
                    headers={
                        "www-authenticate": "Bearer",
                        "content-type": "application/json",
                    },
                    body='{"error": "unauthorized"}',
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.mcp.mcp_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        servers = result.outputs["mcp_servers"]
        assert len(servers) == 1
        assert servers[0]["auth_required"] is True

        obs = result.observations[0]
        assert obs.title == "MCP server discovered: /.well-known/mcp"
        assert "auth-required" in obs.evidence

    @pytest.mark.asyncio
    async def test_no_mcp_found_all_404(self, check, sample_service):
        """Test when no MCP endpoints found (all paths return 404)."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=make_response(status_code=404))
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.mcp.mcp_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        assert result.outputs.get("mcp_servers") is None
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_negative_json_on_mcp_path_without_mcp_indicators(self, check, sample_service):
        """Negative: JSON response on /mcp without any MCP headers, body patterns, or keywords.

        A generic REST API that happens to live at /mcp should NOT be detected
        as an MCP server.
        """
        mock_client = AsyncMock()

        # Return a generic JSON API response with no MCP indicators
        generic_body = json.dumps(
            {
                "version": "2.1.0",
                "uptime": 86400,
                "endpoints": ["/health", "/metrics"],
            }
        )

        async def mock_get(url, **kwargs):
            if "/mcp" in url:
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "application/json",
                        "server": "gunicorn/21.2.0",
                        "x-request-id": "req-001",
                    },
                    body=generic_body,
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.mcp.mcp_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        # No MCP indicators -> no servers discovered
        assert result.outputs.get("mcp_servers") is None
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_negative_non_mcp_sse_endpoint(self, check, sample_service):
        """Negative: A non-MCP SSE endpoint at a non-MCP path should not trigger detection
        unless it is on a probed path. Since /events IS a probed path, use a scenario where
        the SSE endpoint returns event-stream but we verify it IS detected (SSE on probed path
        is a valid indicator). Instead, test that a 200 HTML page on /sse does not trigger."""
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            # All probed paths return 404, except /sse which returns HTML (not event-stream)
            if url.endswith("/sse"):
                return make_response(
                    status_code=200,
                    headers={
                        "content-type": "text/html; charset=utf-8",
                        "server": "Apache/2.4",
                    },
                    body="<html><body>Server Sent Events Dashboard</body></html>",
                    url=url,
                )
            return make_response(status_code=404, url=url)

        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=make_response(status_code=404))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.checks.mcp.mcp_discovery.check.AsyncHttpClient", return_value=mock_client):
            result = await probe_and_grade(check, sample_service, {"services": [sample_service]})

        assert result.success
        # HTML page with no MCP indicators should not produce any servers
        assert result.outputs.get("mcp_servers") is None
        assert len(result.observations) == 0
