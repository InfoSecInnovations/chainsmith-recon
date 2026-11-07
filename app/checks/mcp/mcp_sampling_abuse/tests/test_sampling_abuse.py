"""Tests for mcp_sampling_abuse."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_sampling_abuse import MCPSamplingAbuseCheck
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


class TestMCPSamplingAbuseCheck:
    @pytest.fixture
    def check(self):
        return MCPSamplingAbuseCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_sampling_abuse"

    @pytest.mark.asyncio
    async def test_sampling_exposed(self, check, mcp_server_context):
        """Accessible sampling endpoint with LLM response triggers high-severity open-proxy finding."""
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)

        mock.post = AsyncMock(
            return_value=_jsonrpc_result(
                {
                    "role": "assistant",
                    "content": {"type": "text", "text": "Hello! How can I assist you today?"},
                    "model": "gpt-4",
                    "stopReason": "endTurn",
                }
            )
        )

        with patch("app.checks.mcp.mcp_sampling_abuse.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        high = [o for o in result.observations if o.severity == "high"]
        assert len(high) >= 1
        assert (
            "sampling endpoint exposed" in high[0].title.lower()
            or "open llm proxy" in high[0].title.lower()
        )
        assert "sampling/createMessage" in high[0].title or "sampling" in high[0].evidence.lower()

    @pytest.mark.asyncio
    async def test_sampling_not_available(self, check, mcp_server_context):
        """404 on sampling produces info-level 'not exposed' and no high findings."""
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        mock.post = AsyncMock(return_value=_resp(status_code=404))

        with patch("app.checks.mcp.mcp_sampling_abuse.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        high = [o for o in result.observations if o.severity == "high"]
        assert high == []
        info = [o for o in result.observations if o.severity == "info"]
        assert len(info) == 1
        assert "not exposed" in info[0].title.lower()

    @pytest.mark.asyncio
    async def test_sampling_returns_error_not_flagged(self, check, mcp_server_context):
        """JSON-RPC error on sampling means the endpoint is not accessible -- no high findings."""
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        mock.post = AsyncMock(
            return_value=_jsonrpc_error(
                code=-32601,
                message="Method not found: sampling/createMessage",
            )
        )

        with patch("app.checks.mcp.mcp_sampling_abuse.check.AsyncHttpClient", return_value=mock):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        high = [o for o in result.observations if o.severity in ("high", "critical")]
        assert high == []
