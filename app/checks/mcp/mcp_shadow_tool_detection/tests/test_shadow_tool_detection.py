"""Tests for mcp_shadow_tool_detection."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.mcp.mcp_shadow_tool_detection import ShadowToolDetectionCheck
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
            "name": "read_file",
            "description": "Read a file from disk",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            "risk_level": "high",
            "service_host": "mcp.example.com",
            "server_url": "http://mcp.example.com:8080/mcp",
        },
        {
            "name": "execute_command",
            "description": "Execute shell command",
            "input_schema": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
            "risk_level": "critical",
            "service_host": "mcp.example.com",
            "server_url": "http://mcp.example.com:8080/mcp",
        },
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
        {
            "name": "send_email",
            "description": "Send an email message",
            "input_schema": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "body": {"type": "string"},
                },
            },
            "risk_level": "high",
            "service_host": "mcp.example.com",
            "server_url": "http://mcp.example.com:8080/mcp",
        },
        {
            "name": "get_time",
            "description": "Get current time",
            "input_schema": {},
            "risk_level": "info",
            "service_host": "mcp.example.com",
            "server_url": "http://mcp.example.com:8080/mcp",
        },
    ]
    return ctx


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


class TestShadowToolDetectionCheck:
    @pytest.fixture
    def check(self):
        return ShadowToolDetectionCheck()

    def test_metadata(self, check):
        assert check.name == "mcp_shadow_tool_detection"
        assert "mcp_shadow_tool_risk" in check.produces

    @pytest.mark.asyncio
    async def test_flat_names_flagged(self, check, mcp_tools_context):
        """Flat tool names should be flagged as medium severity."""
        result = await run_and_grade(check, mcp_tools_context)
        assert result.success
        flat_observations = [f for f in result.observations if "flat naming" in f.title.lower()]
        assert len(flat_observations) == 1
        assert flat_observations[0].severity == "medium"
        assert "read_file" in flat_observations[0].evidence

    @pytest.mark.asyncio
    async def test_namespaced_tools_safe(self, check):
        """Fully namespaced tools should produce info (safe) observation, not medium/high."""
        ctx = {
            "mcp_tools": [
                {"name": "server/read_file", "description": "Read", "service_host": "test"},
                {"name": "server/write_file", "description": "Write", "service_host": "test"},
            ],
            "mcp_servers": [],
        }
        result = await run_and_grade(check, ctx)
        info = [f for f in result.observations if f.severity == "info"]
        assert len(info) >= 1
        assert any("namespaced" in f.title.lower() for f in info)
        # No medium or higher for namespace analysis
        namespace_warnings = [
            f
            for f in result.observations
            if "flat" in f.title.lower() and f.severity in ("medium", "high", "critical")
        ]
        assert len(namespace_warnings) == 0

    @pytest.mark.asyncio
    async def test_collision_candidates_detected(self, check, mcp_tools_context):
        """read_file, send_email match common names and should appear in collision_candidates."""
        result = await run_and_grade(check, mcp_tools_context)
        shadow_risk = result.outputs.get("mcp_shadow_tool_risk", {})
        collisions = shadow_risk.get("collision_candidates", [])
        assert "read_file" in collisions
        assert "send_email" in collisions

    @pytest.mark.asyncio
    async def test_no_collision_for_unique_names(self, check):
        """Tools with unique, non-common names should not appear as collision candidates."""
        ctx = {
            "mcp_tools": [
                {
                    "name": "myapp_v2_special_analyzer",
                    "description": "Custom analysis",
                    "service_host": "test",
                },
                {"name": "xk9_formatter", "description": "Format data", "service_host": "test"},
            ],
            "mcp_servers": [],
        }
        result = await run_and_grade(check, ctx)
        shadow_risk = result.outputs.get("mcp_shadow_tool_risk", {})
        collisions = shadow_risk.get("collision_candidates", [])
        assert len(collisions) == 0
        # No collision observation should be emitted
        collision_obs = [f for f in result.observations if "collision" in f.title.lower()]
        assert len(collision_obs) == 0

    @pytest.mark.asyncio
    async def test_list_changed_notification(self, check, mcp_tools_context):
        mock = mock_client_factory()
        mock.post = AsyncMock(return_value=make_response(status_code=200))

        with patch(
            "app.checks.mcp.mcp_shadow_tool_detection.check.AsyncHttpClient", return_value=mock
        ):
            result = await run_and_grade(check, mcp_tools_context)

        high = [f for f in result.observations if f.severity == "high"]
        assert any("list_changed" in f.title.lower() for f in high)
        list_changed_obs = [f for f in high if "list_changed" in f.title.lower()]
        assert "notifications/tools/list_changed" in list_changed_obs[0].evidence
