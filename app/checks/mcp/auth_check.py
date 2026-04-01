"""
app/checks/mcp/auth_check.py - MCP Authentication & Authorization

Tests MCP server auth enforcement at multiple levels:
- No-auth access to tools/list and tool invocations
- Default/common API keys
- Auth scope (discovery vs tool invocation)
- Session reuse/fixation
- CORS cross-origin access

References:
  https://modelcontextprotocol.io/specification
  OWASP LLM Top 10 - LLM07 Insecure Plugin Design
"""

import json
from typing import Any

from app.checks.base import BaseCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


# Common default API keys to test
DEFAULT_KEYS = [
    "mcp-key",
    "default",
    "test",
    "admin",
    "mcp",
    "",
    "changeme",
    "password",
    "secret",
    "api-key",
]


class MCPAuthCheck(BaseCheck):
    """
    Check MCP server authentication and authorization enforcement.

    Tests whether MCP servers require authentication at all levels:
    discovery, tool listing, and tool invocation. Also checks for
    default credentials, session reuse, and CORS misconfiguration.
    """

    name = "mcp_auth_check"
    description = "Check MCP server authentication and authorization enforcement"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_auth_status"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 60.0

    reason = "Local dev MCP servers often have no auth. Testing enforcement reveals unauthenticated tool access."
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
        "OWASP LLM Top 10 - LLM07 Insecure Plugin Design",
    ]
    techniques = ["authentication testing", "authorization bypass", "session analysis"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = context.get("mcp_servers", [])
        auth_status = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            base_path = server.get("path", "")

            try:
                async with AsyncHttpClient(cfg) as client:
                    server_auth = {
                        "url": server_url,
                        "host": host,
                        "tests": {},
                    }

                    # Test 1: No-auth access to tools/list
                    no_auth_result = await self._test_no_auth(
                        client, server_url, base_path, host, result
                    )
                    server_auth["tests"]["no_auth"] = no_auth_result

                    # Test 2: Default API keys
                    default_key_result = await self._test_default_keys(
                        client, server_url, base_path, host, result
                    )
                    server_auth["tests"]["default_keys"] = default_key_result

                    # Test 3: Auth scope — initialize vs tools/list
                    scope_result = await self._test_auth_scope(
                        client, server_url, base_path, host, result, server
                    )
                    server_auth["tests"]["auth_scope"] = scope_result

                    # Test 4: Session reuse
                    session_result = await self._test_session_reuse(
                        client, server_url, base_path, host, result
                    )
                    server_auth["tests"]["session_reuse"] = session_result

                    # Test 5: CORS on MCP endpoints
                    cors_result = await self._test_cors(
                        client, server_url, base_path, host, result
                    )
                    server_auth["tests"]["cors"] = cors_result

                    auth_status.append(server_auth)

            except Exception as e:
                result.errors.append(f"{server_url}: {e}")

        if auth_status:
            result.outputs["mcp_auth_status"] = auth_status

        return result

    async def _test_no_auth(
        self, client, server_url: str, base_path: str, host: str, result: CheckResult
    ) -> dict:
        """Test tools/list and initialize with no auth headers."""
        test_result = {"accessible": False}

        # Try tools/list with no auth
        tools_path = f"{base_path.rstrip('/')}/tools/list" if base_path else "/mcp/tools/list"
        url = self._build_url(server_url, tools_path)

        resp = await client.post(
            url,
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            headers={"Content-Type": "application/json"},
        )

        if not resp.error and resp.status_code == 200:
            test_result["accessible"] = True
            test_result["tools_list"] = True

            # Check if response contains actual tools
            has_tools = self._response_has_tools(resp.body)

            if has_tools:
                result.findings.append(build_finding(
                    check_name=self.name,
                    title="MCP server requires no authentication: tools accessible without credentials",
                    description=(
                        "The MCP server responds to tools/list requests without any authentication. "
                        "An unauthenticated attacker can enumerate all available tools and their schemas."
                    ),
                    severity="critical",
                    evidence=f"URL: {url}\nStatus: {resp.status_code}\nBody: {(resp.body or '')[:500]}",
                    host=host,
                    discriminator="no-auth-tools",
                    raw_data={"url": url, "status": resp.status_code},
                ))
            else:
                result.findings.append(build_finding(
                    check_name=self.name,
                    title="MCP endpoint accessible without authentication",
                    description=(
                        "The MCP server responds to requests without authentication headers, "
                        "though the response may not contain tool data."
                    ),
                    severity="high",
                    evidence=f"URL: {url}\nStatus: {resp.status_code}",
                    host=host,
                    discriminator="no-auth-endpoint",
                    raw_data={"url": url, "status": resp.status_code},
                ))

        elif not resp.error and resp.status_code == 401:
            test_result["accessible"] = False
            result.findings.append(build_finding(
                check_name=self.name,
                title="MCP server enforces authentication",
                description="The MCP server correctly returns 401 for unauthenticated requests.",
                severity="info",
                evidence=f"URL: {url}\nStatus: 401",
                host=host,
                discriminator="auth-enforced",
                raw_data={"url": url, "status": 401},
            ))

        return test_result

    async def _test_default_keys(
        self, client, server_url: str, base_path: str, host: str, result: CheckResult
    ) -> dict:
        """Test common default API keys."""
        test_result = {"accepted_keys": []}

        tools_path = f"{base_path.rstrip('/')}/tools/list" if base_path else "/mcp/tools/list"
        url = self._build_url(server_url, tools_path)

        for key in DEFAULT_KEYS:
            for header_name in ["Authorization", "X-API-Key", "Api-Key"]:
                auth_value = f"Bearer {key}" if header_name == "Authorization" and key else key
                resp = await client.post(
                    url,
                    json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                    headers={"Content-Type": "application/json", header_name: auth_value},
                )

                if not resp.error and resp.status_code == 200 and self._response_has_tools(resp.body):
                    test_result["accepted_keys"].append({
                        "header": header_name,
                        "key": key or "(empty)",
                    })

                    result.findings.append(build_finding(
                        check_name=self.name,
                        title=f"Default API key accepted: '{key or '(empty)'}' grants MCP access",
                        description=(
                            f"The MCP server accepts the default key '{key or '(empty)'}' "
                            f"via {header_name} header, granting access to tool enumeration."
                        ),
                        severity="medium",
                        evidence=f"Header: {header_name}: {auth_value}\nStatus: {resp.status_code}",
                        host=host,
                        discriminator=f"default-key-{key or 'empty'}",
                        raw_data={"header": header_name, "key": key},
                    ))
                    # Found one working key via this header, move to next key
                    break

        return test_result

    async def _test_auth_scope(
        self, client, server_url: str, base_path: str, host: str,
        result: CheckResult, server: dict
    ) -> dict:
        """Test if auth scope differs between initialize and tools/list."""
        test_result = {"scope_mismatch": False}

        init_path = base_path or "/mcp"
        init_url = self._build_url(server_url, init_path)

        # Send initialize — check if it requires auth
        init_resp = await client.post(
            init_url,
            json={
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "chainsmith-recon", "version": "1.0"},
                },
                "id": 1,
            },
            headers={"Content-Type": "application/json"},
        )

        init_requires_auth = (not init_resp.error and init_resp.status_code == 401)

        # Try tools/list
        tools_path = f"{base_path.rstrip('/')}/tools/list" if base_path else "/mcp/tools/list"
        tools_url = self._build_url(server_url, tools_path)

        tools_resp = await client.post(
            tools_url,
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            headers={"Content-Type": "application/json"},
        )

        tools_requires_auth = (not tools_resp.error and tools_resp.status_code == 401)

        if init_requires_auth and not tools_requires_auth:
            test_result["scope_mismatch"] = True
            result.findings.append(build_finding(
                check_name=self.name,
                title="Auth bypass: initialize requires auth but tools/list does not",
                description=(
                    "The MCP server requires authentication for the initialize handshake "
                    "but allows unauthenticated access to tools/list. This inconsistency "
                    "allows attackers to enumerate tools without credentials."
                ),
                severity="high",
                evidence=f"initialize: 401 at {init_url}\ntools/list: {tools_resp.status_code} at {tools_url}",
                host=host,
                discriminator="auth-scope-mismatch",
                raw_data={
                    "init_status": init_resp.status_code,
                    "tools_status": tools_resp.status_code,
                },
            ))

        return test_result

    async def _test_session_reuse(
        self, client, server_url: str, base_path: str, host: str, result: CheckResult
    ) -> dict:
        """Test if MCP session IDs can be reused from a different client context."""
        test_result = {"session_reusable": False}

        init_path = base_path or "/mcp"
        init_url = self._build_url(server_url, init_path)

        # First: get a session ID from initialize
        resp = await client.post(
            init_url,
            json={
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "chainsmith-session-a", "version": "1.0"},
                },
                "id": 1,
            },
            headers={"Content-Type": "application/json"},
        )

        if resp.error or resp.status_code not in (200, 201):
            return test_result

        # Extract session ID from response headers
        session_id = None
        for key, value in resp.headers.items():
            if key.lower() == "mcp-session-id":
                session_id = value
                break

        if not session_id:
            return test_result

        # Try to reuse session ID from a "different client"
        tools_path = f"{base_path.rstrip('/')}/tools/list" if base_path else "/mcp/tools/list"
        tools_url = self._build_url(server_url, tools_path)

        reuse_resp = await client.post(
            tools_url,
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            headers={
                "Content-Type": "application/json",
                "Mcp-Session-Id": session_id,
                "User-Agent": "different-client/1.0",
            },
        )

        if not reuse_resp.error and reuse_resp.status_code == 200:
            test_result["session_reusable"] = True
            result.findings.append(build_finding(
                check_name=self.name,
                title="Session reuse: MCP session ID accepted from different client context",
                description=(
                    "The MCP server accepts a session ID obtained from one client context "
                    "when used by a different client. This enables session hijacking if an "
                    "attacker obtains a valid session ID."
                ),
                severity="high",
                evidence=f"Session ID: {session_id}\nReuse status: {reuse_resp.status_code}",
                host=host,
                discriminator="session-reuse",
                raw_data={"session_id": session_id, "reuse_status": reuse_resp.status_code},
            ))

        return test_result

    async def _test_cors(
        self, client, server_url: str, base_path: str, host: str, result: CheckResult
    ) -> dict:
        """Test CORS headers on MCP endpoints."""
        test_result = {"allows_any_origin": False}

        mcp_path = base_path or "/mcp"
        url = self._build_url(server_url, mcp_path)

        # Send OPTIONS preflight with a foreign origin
        resp = await client.options(
            url,
            headers={
                "Origin": "https://evil.attacker.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )

        if resp.error:
            return test_result

        acao = ""
        for key, value in resp.headers.items():
            if key.lower() == "access-control-allow-origin":
                acao = value
                break

        if acao == "*" or acao == "https://evil.attacker.com":
            test_result["allows_any_origin"] = True
            result.findings.append(build_finding(
                check_name=self.name,
                title="MCP endpoint allows cross-origin requests: browser-based MCP access possible",
                description=(
                    f"The MCP endpoint returns Access-Control-Allow-Origin: {acao}, "
                    "allowing browser-based JavaScript from any origin to interact with "
                    "the MCP server. This enables cross-site MCP attacks."
                ),
                severity="high",
                evidence=f"URL: {url}\nAccess-Control-Allow-Origin: {acao}",
                host=host,
                discriminator="cors-open",
                raw_data={"acao": acao, "url": url},
            ))

        return test_result

    def _build_url(self, server_url: str, path: str) -> str:
        """Build URL from server base and path."""
        # If server_url already contains the base path, use it directly for root-level ops
        base = server_url.rstrip("/")
        if path and not path.startswith("/"):
            path = f"/{path}"
        return f"{base}{path}" if path else base

    def _response_has_tools(self, body: str | None) -> bool:
        """Check if response body contains tool data."""
        if not body:
            return False
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                result = data.get("result", data)
                if isinstance(result, dict) and "tools" in result:
                    return bool(result["tools"])
                if isinstance(result, list) and len(result) > 0:
                    return any("name" in item for item in result if isinstance(item, dict))
            if isinstance(data, list) and len(data) > 0:
                return any("name" in item for item in data if isinstance(item, dict))
        except (json.JSONDecodeError, TypeError):
            pass
        return False
