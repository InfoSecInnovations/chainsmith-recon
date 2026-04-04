"""
app/checks/mcp/transport_security.py - Transport Security Analysis

Analyzes security of MCP transport layer:
- Plain HTTP (no TLS)
- SSE authentication per-connection
- CORS misconfiguration
- Origin header validation

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/basic/transports/
"""

from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig


class TransportSecurityCheck(BaseCheck):
    """
    Analyze MCP transport layer security.

    Checks for plaintext HTTP, SSE auth, CORS headers,
    and Origin header validation on discovered MCP endpoints.
    """

    name = "mcp_transport_security"
    description = "Analyze MCP transport layer security (TLS, CORS, SSE auth)"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_transport_security"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 45.0

    reason = "MCP endpoints may transmit tool results and credentials in cleartext or allow cross-origin access"
    references = [
        "MCP Specification - Transports - https://spec.modelcontextprotocol.io/specification/basic/transports/",
        "OWASP - Transport Layer Security",
    ]
    techniques = ["transport analysis", "CORS testing", "TLS verification"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = context.get("mcp_servers", [])
        transport_findings = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            scheme = service_data.get("scheme", "http")
            transport = server.get("transport", "http")

            server_transport = {
                "url": server_url,
                "host": host,
                "tls": scheme == "https",
                "transport_type": transport,
                "issues": [],
            }

            # Test 1: Plain HTTP check
            if scheme != "https":
                server_transport["issues"].append("no_tls")
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title="MCP served over plain HTTP (no TLS)",
                        description=(
                            f"The MCP endpoint at {server_url} is served over plain HTTP. "
                            "Credentials, tool invocations, and results are transmitted in cleartext, "
                            "allowing network interception."
                        ),
                        severity="high",
                        evidence=f"URL: {server_url}\nScheme: {scheme}",
                        host=host,
                        discriminator="no-tls",
                        raw_data={"url": server_url, "scheme": scheme},
                    )
                )

            try:
                async with AsyncHttpClient(cfg) as client:
                    # Test 2: CORS on MCP endpoints
                    await self._test_cors(client, server_url, host, result, server_transport)

                    # Test 3: Origin header validation
                    await self._test_origin_validation(
                        client, server_url, host, result, server_transport
                    )

                    # Test 4: SSE auth (if SSE transport)
                    if transport == "sse":
                        await self._test_sse_auth(
                            client, server_url, host, result, server_transport
                        )

            except Exception as e:
                result.errors.append(f"Transport security test: {e}")

            transport_findings.append(server_transport)

        if not any(t["issues"] for t in transport_findings) and transport_findings:
            host = transport_findings[0]["host"]
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="Transport security adequate: TLS + origin validation",
                    description="MCP transport layer security checks passed.",
                    severity="info",
                    evidence=f"Servers tested: {len(transport_findings)}",
                    host=host,
                    discriminator="transport-ok",
                )
            )

        if transport_findings:
            result.outputs["mcp_transport_security"] = transport_findings

        return result

    async def _test_cors(
        self, client, server_url: str, host: str, result: CheckResult, server_transport: dict
    ) -> None:
        """Test CORS headers on MCP endpoints."""
        # OPTIONS preflight with evil origin
        resp = await client.options(
            server_url,
            headers={
                "Origin": "https://evil.attacker.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )

        if resp.error:
            return

        acao = ""
        for key, value in resp.headers.items():
            if key.lower() == "access-control-allow-origin":
                acao = value
                break

        if acao == "*":
            server_transport["issues"].append("cors_wildcard")
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="MCP endpoint allows cross-origin requests from any origin (CORS: *)",
                    description=(
                        "The MCP endpoint returns Access-Control-Allow-Origin: *, "
                        "allowing browser-based JavaScript from any origin to interact with "
                        "the MCP server. This enables cross-site MCP exploitation."
                    ),
                    severity="high",
                    evidence=f"URL: {server_url}\nAccess-Control-Allow-Origin: *",
                    host=host,
                    discriminator="cors-wildcard",
                    raw_data={"acao": acao},
                )
            )
        elif acao == "https://evil.attacker.com":
            server_transport["issues"].append("cors_reflects_origin")
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="MCP endpoint reflects arbitrary Origin in CORS response",
                    description=(
                        "The MCP endpoint reflects the request Origin header in "
                        "Access-Control-Allow-Origin, accepting cross-origin requests from any domain."
                    ),
                    severity="high",
                    evidence=f"URL: {server_url}\nOrigin sent: https://evil.attacker.com\nACAO: {acao}",
                    host=host,
                    discriminator="cors-reflect",
                    raw_data={"acao": acao},
                )
            )

    async def _test_origin_validation(
        self, client, server_url: str, host: str, result: CheckResult, server_transport: dict
    ) -> None:
        """Test if POST requests validate Origin header."""
        # Send a JSON-RPC request with a spoofed Origin
        resp = await client.post(
            server_url,
            json={
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1,
            },
            headers={
                "Content-Type": "application/json",
                "Origin": "https://evil.attacker.com",
                "Referer": "https://evil.attacker.com/attack.html",
            },
        )

        if resp.error:
            return

        # If the server returns 200 with data despite foreign origin, it's not validating
        if resp.status_code == 200 and resp.body and '"tools"' in (resp.body or "").lower():
            server_transport["issues"].append("no_origin_validation")
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="MCP endpoint does not validate Origin header",
                    description=(
                        "The MCP server processes requests with a foreign Origin header, "
                        "indicating no Origin/Referer validation. Combined with permissive "
                        "CORS, this enables browser-based MCP attacks."
                    ),
                    severity="medium",
                    evidence=f"URL: {server_url}\nSpoofed Origin: https://evil.attacker.com\nStatus: {resp.status_code}",
                    host=host,
                    discriminator="no-origin-check",
                    raw_data={"status": resp.status_code},
                )
            )

    async def _test_sse_auth(
        self, client, server_url: str, host: str, result: CheckResult, server_transport: dict
    ) -> None:
        """Test if SSE stream is accessible without per-connection auth."""
        # Attempt to connect to SSE endpoint without auth
        resp = await client.get(
            server_url,
            headers={"Accept": "text/event-stream"},
        )

        if resp.error:
            return

        content_type = ""
        for k, v in resp.headers.items():
            if k.lower() == "content-type":
                content_type = v
                break

        if resp.status_code == 200 and "text/event-stream" in content_type:
            server_transport["issues"].append("sse_no_auth")
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="SSE stream accessible without per-connection authentication",
                    description=(
                        "The MCP SSE stream endpoint can be accessed without authentication. "
                        "An attacker can subscribe to the event stream and observe tool invocations "
                        "and results."
                    ),
                    severity="medium",
                    evidence=f"URL: {server_url}\nContent-Type: {content_type}\nStatus: {resp.status_code}",
                    host=host,
                    discriminator="sse-no-auth",
                    raw_data={"content_type": content_type, "status": resp.status_code},
                )
            )
