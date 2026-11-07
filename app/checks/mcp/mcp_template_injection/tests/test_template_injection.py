"""Tests for mcp_template_injection."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_template_injection import ResourceTemplateInjectionCheck
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


class TestResourceTemplateInjectionCheck:
    @pytest.fixture
    def check(self):
        return ResourceTemplateInjectionCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_template_injection"

    @pytest.mark.asyncio
    async def test_sql_injection_detected(self, check, mcp_server_context):
        """SQL-style error in a JSON-RPC response flags a template injection."""
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            method = body.get("method", "")
            if method == "resources/templates/list":
                return _jsonrpc_result(
                    {
                        "resourceTemplates": [
                            {"uriTemplate": "db://query/{table}", "name": "db_query"},
                        ],
                    }
                )
            elif method == "resources/read":
                uri = body.get("params", {}).get("uri", "")
                if any(kw in uri for kw in ("OR", "SELECT", "UNION")):
                    return _jsonrpc_error(
                        code=-32000,
                        message="sql syntax error near 'OR 1=1': no such column",
                    )
                return _jsonrpc_result({})
            return _resp(status_code=404)

        mock.post = mock_post

        with patch(
            "app.checks.mcp.mcp_template_injection.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        vulns = [o for o in result.observations if o.severity in ("high", "critical")]
        assert len(vulns) >= 1
        assert "sql" in vulns[0].title.lower()
        assert "table" in vulns[0].title.lower() or "injection" in vulns[0].title.lower()
        assert vulns[0].severity == "high"

    @pytest.mark.asyncio
    async def test_no_templates_yields_no_observations(self, check, mcp_server_context):
        """Empty template list produces no injection observations."""
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        mock.post = AsyncMock(return_value=_jsonrpc_result({"resourceTemplates": []}))

        with patch(
            "app.checks.mcp.mcp_template_injection.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        assert all(o.severity == "info" or o.check_name != check.name for o in result.observations)

    @pytest.mark.asyncio
    async def test_no_injection_when_payloads_rejected(self, check, mcp_server_context):
        """Templates exist but all injection payloads get benign empty results."""
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)

        async def mock_post(url, **kwargs):
            body = kwargs.get("json", {})
            method = body.get("method", "")
            if method == "resources/templates/list":
                return _jsonrpc_result(
                    {
                        "resourceTemplates": [
                            {"uriTemplate": "db://query/{table}", "name": "db_query"},
                        ],
                    }
                )
            # All reads return empty result (no error leakage)
            return _jsonrpc_result({})

        mock.post = mock_post

        with patch(
            "app.checks.mcp.mcp_template_injection.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_server_context)

        assert result.success
        info = [
            o for o in result.observations if o.severity == "info" and o.check_name == check.name
        ]
        assert len(info) == 1
        assert "properly validated" in info[0].title.lower()
        dangerous = [o for o in result.observations if o.severity in ("high", "critical")]
        assert dangerous == []
