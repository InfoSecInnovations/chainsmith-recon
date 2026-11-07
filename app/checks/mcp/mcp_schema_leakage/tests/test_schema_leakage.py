"""Tests for mcp_schema_leakage."""

from unittest.mock import AsyncMock

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_schema_leakage import ToolSchemaLeakageCheck
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


class TestToolSchemaLeakageCheck:
    @pytest.fixture
    def check(self):
        return ToolSchemaLeakageCheck()

    @pytest.mark.asyncio
    async def test_detects_sensitive_defaults_and_enums(self, check):
        """Internal hostname default + sensitive enum values -> two medium findings."""
        ctx = {
            "mcp_tools": [
                {
                    "name": "db_query",
                    "description": "Query database",
                    "input_schema": {
                        "properties": {
                            "db_host": {"type": "string", "default": "prod-db.internal:5432"},
                            "table": {
                                "type": "string",
                                "enum": ["users", "transactions", "api_keys"],
                            },
                        },
                    },
                    "service_host": "test",
                }
            ]
        }
        result = await run_and_grade(check, ctx)
        assert result.success
        assert "mcp_schema_leaks" in result.outputs

        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) == 2

        # One for the default value revealing internal hostname
        default_obs = [f for f in medium if "default value" in f.title.lower()]
        assert len(default_obs) == 1
        assert "prod-db.internal:5432" in default_obs[0].title
        assert "db_host" in default_obs[0].evidence

        # One for the enum revealing internal table names
        enum_obs = [f for f in medium if "enum" in f.title.lower()]
        assert len(enum_obs) == 1
        assert "users" in enum_obs[0].evidence or "api_keys" in enum_obs[0].evidence

    @pytest.mark.asyncio
    async def test_detects_sensitive_param_names(self, check):
        """Parameters named api_key and bucket_name -> low findings for each."""
        ctx = {
            "mcp_tools": [
                {
                    "name": "storage_tool",
                    "description": "Manage storage",
                    "input_schema": {
                        "properties": {
                            "api_key": {"type": "string"},
                            "bucket_name": {"type": "string"},
                        },
                    },
                    "service_host": "test",
                }
            ]
        }
        result = await run_and_grade(check, ctx)
        low = [f for f in result.observations if f.severity == "low"]
        assert len(low) == 2
        param_names = {f.raw_data["param"] for f in low}
        assert param_names == {"api_key", "bucket_name"}
        # Verify titles describe what was revealed
        for obs in low:
            assert "reveals" in obs.title.lower()
            assert obs.raw_data["param"] in obs.evidence

    @pytest.mark.asyncio
    async def test_clean_schema_no_leaks(self, check):
        """Benign tool schema with no sensitive params -> info, zero leaks."""
        ctx = {
            "mcp_tools": [
                {
                    "name": "get_time",
                    "description": "Get time",
                    "input_schema": {"properties": {"format": {"type": "string"}}},
                    "service_host": "test",
                }
            ]
        }
        result = await run_and_grade(check, ctx)
        assert result.success
        assert "mcp_schema_leaks" not in result.outputs
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) == 1
        assert "no sensitive information" in info[0].title.lower()
        # No medium/high/critical findings
        serious = [f for f in result.observations if f.severity in ("medium", "high", "critical")]
        assert len(serious) == 0
