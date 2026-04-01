"""
app/checks/mcp/invocation_safety.py - MCP Tool Invocation Safety Framework

Shared safety constraints for checks that invoke MCP tools:
- Read-only payload generation from inputSchema
- Response collection capping
- Invocation logging for proof-of-scope compliance
- Destructive payload blocklist

Used by: tool_invocation, resource_traversal, template_injection
"""

import json
import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Maximum bytes to capture from tool invocation responses
MAX_RESPONSE_BYTES = 1000

# Destructive method/action blocklist — NEVER send these
DESTRUCTIVE_PATTERNS = re.compile(
    r"(delete|drop|truncate|remove|destroy|rm\s|rmdir|shutdown|kill|"
    r"format|purge|wipe|overwrite|reset|revoke|disable)",
    re.IGNORECASE,
)

# Safe file paths for read probing
SAFE_READ_PATHS = [
    "/etc/hostname",
    "/dev/null",
    "/proc/version",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

# Safe URLs for fetch probing
SAFE_FETCH_URLS = [
    "http://httpbin.org/get",
    "https://httpbin.org/get",
]

# Safe commands for exec probing
SAFE_COMMANDS = [
    "echo chainsmith-probe",
    "whoami",
    "hostname",
]

# Safe queries for search/db probing
SAFE_QUERIES = [
    "test",
    "SELECT 1",
    "chainsmith-probe",
]


def build_safe_payload(tool: dict) -> dict:
    """
    Build a minimal safe payload from a tool's inputSchema.

    Uses required fields with minimal/benign values.
    Returns empty dict if no schema or cannot build safely.
    """
    schema = tool.get("input_schema", tool.get("inputSchema", {}))
    if not schema or not isinstance(schema, dict):
        return {}

    properties = schema.get("properties", {})
    required = schema.get("required", [])

    if not properties:
        return {}

    payload = {}

    for param_name, param_def in properties.items():
        # Only fill required fields + a few optional ones for completeness
        if param_name not in required and len(payload) >= 2:
            continue

        value = _generate_safe_value(param_name, param_def)
        if value is not None:
            payload[param_name] = value

    return payload


def build_probe_payload(tool: dict, probe_type: str) -> dict:
    """
    Build a targeted probe payload for a specific tool category.

    probe_type: "file", "fetch", "exec", "search", "generic"
    """
    base_payload = build_safe_payload(tool)
    schema = tool.get("input_schema", tool.get("inputSchema", {}))
    properties = schema.get("properties", {}) if schema else {}

    if probe_type == "file":
        for param in ("path", "file", "filename", "file_path", "filepath"):
            if param in properties:
                base_payload[param] = SAFE_READ_PATHS[0]
                break
        else:
            # Try generic first string param
            for param, pdef in properties.items():
                if pdef.get("type") == "string":
                    base_payload[param] = SAFE_READ_PATHS[0]
                    break

    elif probe_type == "fetch":
        for param in ("url", "uri", "href", "endpoint", "target"):
            if param in properties:
                base_payload[param] = SAFE_FETCH_URLS[0]
                break

    elif probe_type == "exec":
        for param in ("command", "cmd", "shell", "code", "script", "input"):
            if param in properties:
                base_payload[param] = SAFE_COMMANDS[0]
                break

    elif probe_type == "search":
        for param in ("query", "q", "search", "term", "input", "text"):
            if param in properties:
                base_payload[param] = SAFE_QUERIES[0]
                break

    return base_payload


def is_payload_safe(payload: dict) -> bool:
    """Check that a payload doesn't contain destructive content."""
    payload_str = json.dumps(payload).lower()
    return not DESTRUCTIVE_PATTERNS.search(payload_str)


def cap_response(body: str | None) -> str:
    """Cap response body to MAX_RESPONSE_BYTES."""
    if not body:
        return ""
    if len(body) > MAX_RESPONSE_BYTES:
        return body[:MAX_RESPONSE_BYTES] + f"... (truncated, {len(body)} total bytes)"
    return body


def classify_tool_probe_type(tool: dict) -> str:
    """Determine which probe type to use for a tool based on its name/description/schema."""
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    schema = tool.get("input_schema", tool.get("inputSchema", {}))
    props = schema.get("properties", {}) if schema else {}
    prop_names = {p.lower() for p in props.keys()}
    combined = f"{name} {desc}"

    if any(kw in combined for kw in ["file", "read_file", "write_file", "fs_read"]):
        return "file"
    if any(kw in combined for kw in ["http", "fetch", "curl", "wget", "request", "url"]):
        return "fetch"
    if any(kw in combined for kw in ["exec", "command", "shell", "eval", "run_code", "bash"]):
        return "exec"
    if any(kw in combined for kw in ["query", "search", "sql", "database", "find"]):
        return "search"

    # Check schema params
    if prop_names & {"path", "file", "filename", "filepath"}:
        return "file"
    if prop_names & {"url", "uri", "href"}:
        return "fetch"
    if prop_names & {"command", "cmd", "code", "script"}:
        return "exec"
    if prop_names & {"query", "q", "search"}:
        return "search"

    return "generic"


def log_invocation(tool_name: str, payload: dict, response_status: int | None, response_body: str) -> dict:
    """Create an invocation log entry for proof-of-scope compliance."""
    entry = {
        "tool": tool_name,
        "payload": payload,
        "response_status": response_status,
        "response_preview": cap_response(response_body),
        "safe": is_payload_safe(payload),
    }
    logger.info(f"MCP tool invocation: {tool_name} -> status={response_status}")
    return entry


def _generate_safe_value(param_name: str, param_def: dict) -> Any:
    """Generate a safe value for a parameter based on its schema definition."""
    param_type = param_def.get("type", "string")
    default = param_def.get("default")

    if default is not None:
        return default

    # Use enum first value if available
    enum = param_def.get("enum")
    if enum and len(enum) > 0:
        return enum[0]

    if param_type == "string":
        return "test"
    elif param_type == "integer":
        return param_def.get("minimum", 1)
    elif param_type == "number":
        return param_def.get("minimum", 1.0)
    elif param_type == "boolean":
        return False
    elif param_type == "array":
        return []
    elif param_type == "object":
        return {}

    return "test"
