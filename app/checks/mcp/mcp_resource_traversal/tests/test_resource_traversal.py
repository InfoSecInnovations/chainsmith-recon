"""Tests for mcp_resource_traversal."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_resource_traversal import MCPResourceTraversalCheck
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
    ]
    return ctx


def _resp(body="", status_code=200, error=None):
    """Build an HttpResponse with minimal boilerplate."""
    return HttpResponse(
        url="http://test",
        status_code=status_code,
        headers={},
        body=body,
        elapsed_ms=10.0,
        error=error,
    )


def _jsonrpc_result(result_payload):
    """Return a 200 HttpResponse wrapping a JSON-RPC result."""
    return _resp(body=json.dumps({"jsonrpc": "2.0", "result": result_payload, "id": 1}))


def _jsonrpc_error(code=-1, message="error"):
    """Return a 200 HttpResponse wrapping a JSON-RPC error."""
    return _resp(
        body=json.dumps({"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": 1})
    )


class TestMCPResourceTraversalCheck:
    @pytest.fixture
    def check(self):
        return MCPResourceTraversalCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_resource_traversal"
        assert check.intrusive is True

    @pytest.mark.asyncio
    async def test_traversal_detected(self, check, mcp_server_context):
        """Passwd-style content in a traversal URI triggers a critical observation."""
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            uri = body.get("params", {}).get("uri", "")
            if "passwd" in uri:
                return _jsonrpc_result(
                    {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "text/plain",
                                "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                            }
                        ],
                    }
                )
            return _jsonrpc_result({})

        mock.post = mock_post

        with patch(
            "app.checks.mcp.mcp_resource_traversal.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        critical = [o for o in result.observations if o.severity == "critical"]
        assert len(critical) >= 1
        assert "path traversal" in critical[0].title.lower()
        assert "root:" in critical[0].evidence

    @pytest.mark.asyncio
    async def test_traversal_blocked(self, check, mcp_server_context):
        """When every probe returns a JSON-RPC error, only an info observation appears."""
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        mock.post = AsyncMock(return_value=_jsonrpc_error(message="Access denied"))

        with patch(
            "app.checks.mcp.mcp_resource_traversal.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        info = [o for o in result.observations if o.severity == "info"]
        assert len(info) == 1
        assert "validation enforced" in info[0].title.lower()
        # No high/critical observations when everything is blocked
        dangerous = [o for o in result.observations if o.severity in ("high", "critical")]
        assert dangerous == []

    @pytest.mark.asyncio
    async def test_payloads_sharing_an_attack_type_yield_one_observation(
        self, check, mcp_server_context
    ):
        """passwd and hosts are both `path_traversal`: one observation names both.

        One verdict per payload minted the same observation id twice, and the
        duplicate primary key sent the rest of the scan's observations to scratch.
        """
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)

        async def mock_post(url, **kwargs):
            uri = kwargs.get("json", {}).get("params", {}).get("uri", "")
            if uri.startswith("file://"):
                return _jsonrpc_error(message=f"No such resource: /opt/app/resources/{uri[7:]}")
            return _jsonrpc_error(message="Access denied")

        mock.post = mock_post

        with patch(
            "app.checks.mcp.mcp_resource_traversal.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

        ids = [o.id for o in result.observations]
        assert len(ids) == len(set(ids))
        # path_traversal (x2), absolute_file, encoded_traversal, null_byte
        assert len(ids) == 4

        leak = [o for o in result.observations if o.id.endswith("traversal-leak-path_traversal")]
        assert len(leak) == 1
        assert leak[0].severity == "medium"
        assert "file://../../etc/passwd" in leak[0].evidence
        assert "file://../../etc/hosts" in leak[0].evidence
        assert len(leak[0].evidence_ids) == 2
