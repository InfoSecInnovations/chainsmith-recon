"""
app/checks/mcp/resource_traversal.py - MCP Resource URI Traversal

Tests MCP resources for path traversal and SSRF via resource URIs.
Sends resources/read with crafted URIs to probe for unauthorized access.

Safety: read-only probes, no destructive payloads, response capped.

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/server/resources/
  CWE-22 Path Traversal
  CWE-918 SSRF
"""

import json
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.checks.mcp.invocation_safety import cap_response, log_invocation
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig

# Traversal payloads — read-only probes only
TRAVERSAL_PAYLOADS = [
    ("file://../../etc/passwd", "path_traversal", "Unix passwd file"),
    ("file://../../etc/hosts", "path_traversal", "Unix hosts file"),
    ("file:///etc/hostname", "absolute_file", "Unix hostname"),
    ("file://....//....//etc/passwd", "encoded_traversal", "Double-encoded traversal"),
    ("file://../../etc/passwd%00.txt", "null_byte", "Null byte injection"),
]

# SSRF payloads — probing for internal services
SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "cloud_metadata", "AWS metadata endpoint"),
    ("http://169.254.169.254/metadata/instance", "cloud_metadata", "Azure metadata endpoint"),
    (
        "http://metadata.google.internal/computeMetadata/v1/",
        "cloud_metadata",
        "GCP metadata endpoint",
    ),
    ("http://localhost:6379/", "internal_service", "Local Redis"),
    ("http://127.0.0.1:9200/", "internal_service", "Local Elasticsearch"),
]

# Protocol smuggling
PROTOCOL_PAYLOADS = [
    ("gopher://localhost:6379/_PING", "protocol_smuggle", "Gopher protocol to Redis"),
    ("dict://localhost:6379/INFO", "protocol_smuggle", "Dict protocol to Redis"),
]


class MCPResourceTraversalCheck(BaseCheck):
    """
    Test MCP resource URIs for path traversal and SSRF.

    Sends resources/read with crafted URIs and analyzes responses
    for data leakage or successful traversal.
    """

    name = "mcp_resource_traversal"
    description = "Test MCP resource URIs for path traversal and SSRF"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_resource_traversal_results"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 90.0
    intrusive = True

    reason = "MCP resources accessed by URI may be vulnerable to path traversal and SSRF"
    references = [
        "MCP Specification - Resources - https://spec.modelcontextprotocol.io/specification/server/resources/",
        "CWE-22 Path Traversal",
        "CWE-918 Server-Side Request Forgery",
    ]
    techniques = ["path traversal", "SSRF", "protocol smuggling"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = context.get("mcp_servers", [])
        traversal_results = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            capabilities = server.get("capabilities", [])

            if not server_url:
                continue

            # Only test servers that declare resources capability
            (
                any("resource" in str(c).lower() for c in capabilities) if capabilities else True
            )  # If no caps listed, probe anyway

            try:
                async with AsyncHttpClient(cfg) as client:
                    # First: enumerate resources to understand URI format
                    await self._enumerate_resources(client, server_url)

                    # Test path traversal
                    for uri, attack_type, _desc in TRAVERSAL_PAYLOADS:
                        r = await self._probe_resource(client, server_url, uri)
                        inv = log_invocation(
                            f"resources/read:{attack_type}",
                            {"uri": uri},
                            r.get("status"),
                            r.get("body", ""),
                        )
                        traversal_results.append(inv)

                        if r["success"] and r["has_content"]:
                            # Check for actual file content indicators
                            body = r["body"]
                            if self._looks_like_file_content(body, attack_type):
                                result.observations.append(
                                    build_observation(
                                        check_name=self.name,
                                        title=f"Resource path traversal: {uri} returned file contents",
                                        description=f"The MCP resource endpoint returned actual file contents for traversal URI: {uri}",
                                        severity="critical",
                                        evidence=f"URI: {uri}\nResponse: {cap_response(body)[:300]}",
                                        host=host,
                                        discriminator=f"traversal-{attack_type}",
                                        raw_data={"uri": uri, "body": cap_response(body)},
                                    )
                                )
                            elif r.get("error_leaks_path"):
                                result.observations.append(
                                    build_observation(
                                        check_name=self.name,
                                        title="Resource traversal blocked but error leaks file path",
                                        description=f"Error message reveals internal path structure for URI: {uri}",
                                        severity="medium",
                                        evidence=f"URI: {uri}\nError: {cap_response(body)[:300]}",
                                        host=host,
                                        discriminator=f"traversal-leak-{attack_type}",
                                        raw_data={"uri": uri, "body": cap_response(body)},
                                    )
                                )

                    # Test SSRF
                    for uri, attack_type, _desc in SSRF_PAYLOADS:
                        r = await self._probe_resource(client, server_url, uri)
                        inv = log_invocation(
                            f"resources/read:{attack_type}",
                            {"uri": uri},
                            r.get("status"),
                            r.get("body", ""),
                        )
                        traversal_results.append(inv)

                        if r["success"] and r["has_content"]:
                            if self._looks_like_ssrf_content(r["body"], attack_type):
                                result.observations.append(
                                    build_observation(
                                        check_name=self.name,
                                        title=f"SSRF via MCP resource: {uri} returned internal data",
                                        description=f"The MCP resource endpoint fetched an internal URL: {uri}",
                                        severity="critical",
                                        evidence=f"URI: {uri}\nResponse: {cap_response(r['body'])[:300]}",
                                        host=host,
                                        discriminator=f"ssrf-{attack_type}",
                                        raw_data={"uri": uri, "body": cap_response(r["body"])},
                                    )
                                )

                    # Test protocol smuggling
                    for uri, attack_type, _desc in PROTOCOL_PAYLOADS:
                        r = await self._probe_resource(client, server_url, uri)
                        if r["success"] and r["has_content"]:
                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"Resource URI accepts {uri.split(':')[0]}:// protocol",
                                    description=f"The MCP resource endpoint accepted a non-standard protocol URI: {uri}",
                                    severity="high",
                                    evidence=f"URI: {uri}\nResponse: {cap_response(r['body'])[:300]}",
                                    host=host,
                                    discriminator=f"protocol-{attack_type}",
                                    raw_data={"uri": uri},
                                )
                            )

                    # If nothing found
                    if not any(f.check_name == self.name for f in result.observations):
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title="Resource URI validation enforced (traversal attempts rejected)",
                                description="MCP resource URIs are properly validated against traversal and SSRF.",
                                severity="info",
                                evidence=f"Server: {server_url}\nPayloads tested: {len(TRAVERSAL_PAYLOADS) + len(SSRF_PAYLOADS) + len(PROTOCOL_PAYLOADS)}",
                                host=host,
                                discriminator="resource-safe",
                            )
                        )

            except Exception as e:
                result.errors.append(f"Resource traversal on {server_url}: {e}")

        if traversal_results:
            result.outputs["mcp_resource_traversal_results"] = traversal_results

        return result

    async def _enumerate_resources(self, client, server_url: str) -> list[dict]:
        """Enumerate available resources via resources/list."""
        resp = await client.post(
            server_url,
            json={"jsonrpc": "2.0", "method": "resources/list", "id": 1},
            headers={"Content-Type": "application/json"},
        )
        if resp.error or resp.status_code != 200 or not resp.body:
            return []
        try:
            data = json.loads(resp.body)
            result = data.get("result", data)
            if isinstance(result, dict) and "resources" in result:
                return result["resources"]
            if isinstance(result, list):
                return result
        except (json.JSONDecodeError, TypeError):
            pass
        return []

    async def _probe_resource(self, client, server_url: str, uri: str) -> dict:
        """Send resources/read with a crafted URI and analyze response."""
        resp = await client.post(
            server_url,
            json={
                "jsonrpc": "2.0",
                "method": "resources/read",
                "params": {"uri": uri},
                "id": 1,
            },
            headers={"Content-Type": "application/json"},
        )

        probe_result = {
            "success": False,
            "has_content": False,
            "body": "",
            "status": resp.status_code if not resp.error else None,
            "error_leaks_path": False,
        }

        if resp.error:
            return probe_result

        probe_result["body"] = resp.body or ""
        probe_result["status"] = resp.status_code

        if resp.status_code == 200 and resp.body:
            try:
                data = json.loads(resp.body)
                # Check for JSON-RPC error
                if isinstance(data, dict) and "error" in data:
                    error_msg = str(data["error"])
                    # Check if error leaks path info
                    if any(p in error_msg for p in ["/opt/", "/var/", "/home/", "C:\\", "/etc/"]):
                        probe_result["error_leaks_path"] = True
                        probe_result["has_content"] = True
                    return probe_result

                # Check for actual content in result
                result_data = data.get("result", data)
                if isinstance(result_data, dict) and "contents" in result_data:
                    contents = result_data["contents"]
                    if contents and isinstance(contents, list) and len(contents) > 0:
                        probe_result["success"] = True
                        probe_result["has_content"] = True
                        # Flatten content for analysis
                        probe_result["body"] = str(contents[0])
                elif result_data and str(result_data) not in ("{}", "[]", "None", ""):
                    probe_result["success"] = True
                    probe_result["has_content"] = True
            except (json.JSONDecodeError, TypeError):
                if len(resp.body) > 10:
                    probe_result["success"] = True
                    probe_result["has_content"] = True

        return probe_result

    def _looks_like_file_content(self, body: str, attack_type: str) -> bool:
        """Check if response looks like actual file contents."""
        if not body:
            return False
        body_lower = body.lower()
        return any(
            indicator in body_lower
            for indicator in [
                "root:",
                "/bin/bash",
                "/bin/sh",  # /etc/passwd
                "localhost",
                "127.0.0.1",  # /etc/hosts
                "linux",
                "darwin",  # /etc/hostname, /proc/version
            ]
        )

    def _looks_like_ssrf_content(self, body: str, attack_type: str) -> bool:
        """Check if response looks like internal service data."""
        if not body:
            return False
        body_lower = body.lower()
        if attack_type == "cloud_metadata":
            return any(
                kw in body_lower
                for kw in [
                    "ami-id",
                    "instance-id",
                    "availability-zone",
                    "compute",
                    "metadata",
                    "project-id",
                ]
            )
        elif attack_type == "internal_service":
            return any(
                kw in body_lower
                for kw in [
                    "redis",
                    "connected_clients",
                    "elasticsearch",
                    "cluster_name",
                    "version",
                    "tagline",
                ]
            )
        return len(body) > 20
