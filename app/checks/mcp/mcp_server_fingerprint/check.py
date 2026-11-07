"""
app/checks/mcp/server_fingerprint.py - MCP Server Fingerprinting

Identifies MCP server implementation from response patterns,
error messages, capability sets, and protocol behavior.

Operates on data already collected by MCPDiscoveryCheck.

**Probe/grade.** Most of the signal is upstream context —
the `serverInfo` and capabilities `mcp_discovery` already recorded — so the
probe's only request is an error-fingerprint POST, made and recorded *only* when
`serverInfo` did not already identify the server. One candidate per server
(§0.15). The upstream `serverInfo`/capabilities the verdict mostly rests on are
recorded on the candidate as a `local` exchange (the `mcp_schema_leakage`
precedent): a re-grade of a stored corpus has no scan context to read them from.
`_identify()` is the one routine both halves call (§0.12): the probe builds its
`mcp_server_implementations` output with it, `grade()` re-runs it over the
`local` exchange and the recorded error-probe body.

**Fixed**: the discriminator embeds the implementation name
(`impl-<name>` / `impl-custom`), an unbounded set, so there is no `observations:`
map and `grade()` places the tier (`info` identified, `low` custom). Confidence
is where the split pays: a `serverInfo.name` is **self-reported** — a server can
call itself anything — and an error-string match rests on output a proxy or WAF
can rewrite.

References:
  https://modelcontextprotocol.io/specification
"""

import json
import re
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Server fingerprint signatures
SERVER_SIGNATURES = [
    {
        "name": "Official TypeScript SDK",
        "patterns": {
            "server_name": [r"@modelcontextprotocol/sdk", r"mcp-typescript"],
            "error_format": [r"MCP error", r"JsonRpcError"],
            "capabilities": ["tools", "resources", "prompts"],
        },
        "version_field": "version",
    },
    {
        "name": "Official Python SDK (mcp)",
        "patterns": {
            "server_name": [r"mcp", r"python-mcp"],
            "error_format": [r"McpError", r"Traceback", r"asyncio"],
            "capabilities": ["tools", "resources", "prompts"],
        },
        "version_field": "version",
    },
    {
        "name": "FastMCP",
        "patterns": {
            "server_name": [r"fastmcp", r"FastMCP"],
            "error_format": [r"FastMCP", r"fastmcp\."],
            "capabilities": ["tools"],
        },
        "version_field": "version",
    },
    {
        "name": "LangChain MCP Adapter",
        "patterns": {
            "server_name": [r"langchain", r"langchain-mcp"],
            "error_format": [r"langchain"],
        },
    },
    {
        "name": "Claude Desktop MCP",
        "patterns": {
            "server_name": [r"claude", r"anthropic"],
        },
    },
    {
        "name": "Cursor MCP",
        "patterns": {
            "server_name": [r"cursor"],
        },
    },
    {
        "name": "Ollama MCP Bridge",
        "patterns": {
            "server_name": [r"ollama"],
            "error_format": [r"ollama"],
        },
    },
]


class MCPServerFingerprintCheck(BaseCheck):
    """
    Fingerprint MCP server implementations.

    Identifies the MCP server framework/SDK from server info,
    error message patterns, and capability signatures.
    """

    name = "mcp_server_fingerprint"
    description = "Identify MCP server implementation and version"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_server_implementations"]
    service_types = ["ai", "api", "http"]

    reason = "Identifying the MCP server implementation enables targeted vulnerability research"
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
        "CWE-200 Exposure of Sensitive Information",
    ]
    techniques = ["fingerprinting", "version detection", "error analysis"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        mcp_servers = context.get("mcp_servers", [])
        implementations = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            server_info = server.get("server_info", {})
            capabilities = server.get("capabilities", [])

            # Only probe for an error fingerprint when serverInfo did not already
            # name the server — the original's Step 2 condition.
            pre = self._match_server_info(server_info) if server_info else None
            error_exchange: Exchange | None = None
            if not (pre and pre.get("identified")):
                try:
                    async with AsyncHttpClient(cfg) as client:
                        payload = {
                            "jsonrpc": "2.0",
                            "method": "nonexistent/method_that_does_not_exist",
                            "id": 999,
                        }
                        resp = await client.post(server_url, json=payload, headers=JSON_HEADERS)
                        error_exchange = exchange_from_response(
                            resp,
                            check_name=self.name,
                            scan_id=scan_id,
                            host=host,
                            method="POST",
                            request_headers=JSON_HEADERS,
                            request_json=payload,
                        )
                except Exception as e:
                    result.errors.append(f"Fingerprint probe: {e}")

            impl = self._identify(server_url, host, server_info, capabilities, error_exchange)
            implementations.append(impl)

            upstream = capture.record_exchange(
                "local",
                host,
                request_body=f"mcp_server_fingerprint mcp_servers {server_url}",
                request_headers={"source": "mcp_servers"},
                response_body=json.dumps(
                    {"server_info": server_info, "capabilities": capabilities}, default=str
                ),
            )
            candidate = self.create_candidate(host=host, target_url=server_url)
            candidate.attach(upstream)
            candidate.attach(error_exchange)
            result.candidates.append(candidate)

        if implementations:
            result.outputs["mcp_server_implementations"] = implementations

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        upstream, upstream_exchange = self._upstream_from(evidence)
        server_info = upstream.get("server_info") or {}
        capabilities = upstream.get("capabilities") or []
        server_url = ctx.target_url or ""

        error_exchange = next((e for e in evidence if (e.request_method or "") == "POST"), None)
        impl = self._identify(server_url, ctx.host, server_info, capabilities, error_exchange)

        evidence_ids = [e.id for e in (upstream_exchange, error_exchange) if e is not None]

        if impl["identified"]:
            version_str = f" v{impl['version']}" if impl.get("version") else ""
            confidence, why = self._confidence(impl)
            return [
                Verdict(
                    severity="info",
                    confidence=confidence,
                    discriminator=f"impl-{impl['implementation'].lower().replace(' ', '-')}",
                    title=f"MCP server identified: {impl['implementation']}{version_str}",
                    description=(
                        f"The MCP server at {server_url} is running "
                        f"{impl['implementation']}{version_str} "
                        f"(confidence: {impl['confidence']})."
                    ),
                    evidence=self._build_evidence(impl, server_info),
                    reasoning=why,
                    signals={
                        "match_method": impl.get("match_method"),
                        "confidence_label": impl.get("confidence"),
                    },
                    references=self.references,
                    raw_data=impl,
                    tier=ctx.tier,
                    evidence_ids=evidence_ids,
                )
            ]

        return [
            Verdict(
                severity="low",
                confidence=0.5,
                discriminator="impl-custom",
                title="MCP server is custom implementation (non-standard)",
                description=(
                    "The MCP server could not be matched to a known implementation. "
                    "Custom implementations may have unique vulnerabilities."
                ),
                evidence=f"URL: {server_url}\nServer info: {json.dumps(server_info)[:200]}",
                reasoning=(
                    "no serverInfo name, error string or capability set matched a known "
                    "signature; the 'custom' verdict is the absence of a match against the fixed "
                    "signature table, so a known SDK that hides its name reads the same"
                ),
                signals={"match_method": impl.get("match_method")},
                references=self.references,
                raw_data=impl,
                tier=ctx.tier,
                evidence_ids=evidence_ids,
            )
        ]

    @staticmethod
    def _upstream_from(evidence: Evidence) -> tuple[dict, Exchange | None]:
        """The serverInfo/capabilities recorded on the candidate's `local` exchange."""
        for exchange in evidence:
            if exchange.protocol != "local" or not exchange.response_body:
                continue
            try:
                data = json.loads(exchange.response_body)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                return data, exchange
        return {}, None

    @staticmethod
    def _confidence(impl: dict) -> tuple[float, str]:
        method = impl.get("match_method")
        if method == "server_name":
            return 0.85, (
                "the serverInfo name matched a known SDK signature; strong, but a name is "
                "self-reported and a server can announce whatever it likes"
            )
        if method == "server_name_raw":
            return 0.6, (
                "the server volunteered a name that matched no signature, so the identity is "
                "exactly what the server chose to call itself — self-reported, unverified"
            )
        if method == "error_format":
            return 0.6, (
                "fingerprinted from an error-response string; distinctive, but error text is "
                "output a reverse proxy or WAF can rewrite or suppress"
            )
        if method == "capabilities":
            return 0.4, (
                "identified only by the shape of the capability set, which many SDKs share"
            )
        return 0.5, "matched a signature with no stronger corroboration"

    # ── The routine both halves share ────────────────────────────────

    def _identify(
        self,
        server_url: str,
        host: str,
        server_info: dict,
        capabilities: list,
        error_exchange: Exchange | None,
    ) -> dict:
        """Rebuild the implementation dict from serverInfo, an error exchange and
        capabilities — the original's four-step ladder, side-effect free."""
        impl = {
            "url": server_url,
            "host": host,
            "identified": False,
            "implementation": None,
            "version": None,
            "confidence": "low",
        }

        if server_info:
            match = self._match_server_info(server_info)
            if match:
                impl.update(match)

        if not impl["identified"] and error_exchange is not None:
            error_match = self._error_fingerprint_from(error_exchange)
            if error_match:
                impl.update(error_match)

        if not impl["identified"] and capabilities:
            cap_match = self._match_capabilities(capabilities)
            if cap_match:
                impl.update(cap_match)

        if not impl["identified"]:
            impl["implementation"] = "Unknown/Custom"
            impl["confidence"] = "low"

        return impl

    def _match_server_info(self, server_info: dict) -> dict | None:
        """Match serverInfo fields against known signatures."""
        name = server_info.get("name", "").lower()
        version = server_info.get("version", "")

        for sig in SERVER_SIGNATURES:
            for pattern in sig["patterns"].get("server_name", []):
                if re.search(pattern, name, re.IGNORECASE):
                    return {
                        "identified": True,
                        "implementation": sig["name"],
                        "version": version or None,
                        "confidence": "high",
                        "match_method": "server_name",
                    }

        # If we have a name but no match, it's still useful info
        if name:
            return {
                "identified": True,
                "implementation": server_info.get("name", name),
                "version": version or None,
                "confidence": "medium",
                "match_method": "server_name_raw",
            }

        return None

    def _error_fingerprint_from(self, exchange: Exchange) -> dict | None:
        """Fingerprint from a recorded error-probe response body."""
        if exchange.error or not exchange.response_body:
            return None

        body = exchange.response_body.lower()

        for sig in SERVER_SIGNATURES:
            for pattern in sig["patterns"].get("error_format", []):
                if re.search(pattern, body, re.IGNORECASE):
                    return {
                        "identified": True,
                        "implementation": sig["name"],
                        "version": None,
                        "confidence": "medium",
                        "match_method": "error_format",
                    }

        # Check for Python-style tracebacks
        if "traceback" in body or 'file "' in body:
            return {
                "identified": True,
                "implementation": "Python-based (unknown SDK)",
                "version": None,
                "confidence": "low",
                "match_method": "error_format",
            }

        # Check for Node.js-style errors
        if "at object." in body or "at module." in body or "node_modules" in body:
            return {
                "identified": True,
                "implementation": "Node.js-based (unknown SDK)",
                "version": None,
                "confidence": "low",
                "match_method": "error_format",
            }

        return None

    def _match_capabilities(self, capabilities: list) -> dict | None:
        """Heuristic matching based on capability set."""
        cap_set = {c.lower() if isinstance(c, str) else "" for c in capabilities}

        # Most complete capability set suggests official SDK
        if {"tools", "resources", "prompts"}.issubset(cap_set):
            return {
                "identified": False,  # Low confidence, just a hint
                "implementation": "Full MCP SDK (tools+resources+prompts)",
                "confidence": "low",
                "match_method": "capabilities",
            }

        return None

    def _build_evidence(self, impl: dict, server_info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Implementation: {impl.get('implementation', 'unknown')}",
            f"Version: {impl.get('version', 'unknown')}",
            f"Confidence: {impl.get('confidence', 'unknown')}",
            f"Match method: {impl.get('match_method', 'unknown')}",
        ]

        if server_info:
            lines.append(f"Server info: {json.dumps(server_info)[:200]}")

        return "\n".join(lines)
