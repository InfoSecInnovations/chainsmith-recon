"""
app/checks/mcp/undeclared_capabilities.py - Undeclared Capability Probing

Probes MCP servers for capabilities not declared in the initialize response.
Tests tools/list, resources/list, prompts/list, sampling, and non-standard
methods even when not declared.

**Probe/grade.** The probe sends one JSON-RPC request per
undeclared standard capability and per non-standard method, records each, and
hands them over as one candidate per server. `grade()` re-reads the recorded
requests, recovers which method each carried off its own request body (never a
remembered list, §0.14), and places the verdict. `_accessible()` is the one
reading both halves share (§0.12): a response is "accessible" only if it carries
a non-empty JSON-RPC `result` and no `error`.

Declared capabilities are never probed, so they simply do not appear in the
evidence — nothing about the split changes that.

**Fixed**: the standard capabilities and non-standard
methods are two closed tables, so the contract carries the full map, each entry
at the single severity its family emits. Confidence is where the split pays: a
JSON-RPC `result` is stronger evidence for a standard method than a bare 200 is
for a non-standard one, which a catch-all route answers for any path.

References:
  https://modelcontextprotocol.io/specification
"""

import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Standard MCP capabilities and their probe methods
STANDARD_CAPABILITIES = [
    ("tools", "tools/list", "Tool enumeration"),
    ("resources", "resources/list", "Resource enumeration"),
    ("prompts", "prompts/list", "Prompt template listing"),
    ("sampling", "sampling/createMessage", "LLM sampling/proxy"),
]

# Non-standard methods that may reveal admin/debug interfaces
NON_STANDARD_METHODS = [
    ("admin/status", "Admin status endpoint"),
    ("debug/info", "Debug info endpoint"),
    ("internal/config", "Internal configuration"),
    ("server/info", "Server information"),
    ("server/status", "Server status"),
    ("health", "Health check"),
    ("metrics", "Metrics endpoint"),
    ("logging/setLevel", "Log level control"),
]

# Method -> (capability, description) for the standard table.
_STANDARD_BY_METHOD = {method: (cap, desc) for cap, method, desc in STANDARD_CAPABILITIES}
# Method -> description for the non-standard table.
_NONSTANDARD_BY_METHOD = dict(NON_STANDARD_METHODS)


class UndeclaredCapabilityCheck(BaseCheck):
    """
    Probe for MCP capabilities not declared in initialize response.

    Some servers implement capabilities but forget to declare them,
    or expose admin/debug methods not part of the MCP spec.
    """

    name = "mcp_undeclared_capabilities"
    description = "Probe for MCP capabilities not declared in initialize response"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_undeclared_capabilities"]
    service_types = ["ai", "api", "http"]

    reason = "Servers may implement undeclared capabilities, exposing hidden attack surface"
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
    ]
    techniques = ["capability probing", "hidden endpoint discovery"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        mcp_servers = context.get("mcp_servers", [])
        undeclared = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")
            declared_caps = {str(c).lower() for c in server.get("capabilities", [])}

            if not server_url:
                continue

            exchanges: list[Exchange] = []

            try:
                async with AsyncHttpClient(cfg) as client:
                    # Standard capabilities not in the declared set
                    for cap_name, method, _desc in STANDARD_CAPABILITIES:
                        if cap_name.lower() in declared_caps:
                            continue
                        exchanges.append(
                            await self._probe_method(client, server_url, method, scan_id, host)
                        )

                    # Non-standard methods
                    for method, _desc in NON_STANDARD_METHODS:
                        exchanges.append(
                            await self._probe_method(client, server_url, method, scan_id, host)
                        )

            except Exception as e:
                result.errors.append(f"Capability probe on {server_url}: {e}")

            if exchanges:
                candidate = self.create_candidate(
                    host=host,
                    discriminator=f"caps-{host}",
                    target_url=server_url,
                )
                for exchange in exchanges:
                    candidate.attach(exchange)
                result.candidates.append(candidate)

            undeclared.append(
                {
                    "url": server_url,
                    "host": host,
                    "declared": list(declared_caps),
                    "undeclared_accessible": self._accessible_standard(exchanges),
                    "non_standard_accessible": self._accessible_nonstandard(exchanges),
                }
            )

        if undeclared:
            result.outputs["mcp_undeclared_capabilities"] = undeclared

        return result

    async def _probe_method(
        self, client, server_url: str, method: str, scan_id: str, host: str
    ) -> Exchange:
        """Send one JSON-RPC method call and record it."""
        payload = {"jsonrpc": "2.0", "method": method, "id": 1}
        resp = await client.post(server_url, json=payload, headers=JSON_HEADERS)
        return exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="POST",
            request_headers=JSON_HEADERS,
            request_json=payload,
        )

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        server_url = ctx.target_url or (ctx.target.url if ctx.target else "")
        verdicts: list[Verdict] = []

        for exchange in evidence:
            method = self._method_of(exchange)
            if not self._accessible(exchange):
                continue

            if method in _STANDARD_BY_METHOD:
                cap, desc = _STANDARD_BY_METHOD[method]
                verdicts.append(
                    Verdict(
                        severity="high",
                        confidence=0.7,
                        discriminator=f"undeclared-{cap}",
                        title=f"Undeclared capability accessible: {method} returns data but {cap} not declared",
                        description=(
                            f"The server responds to {method} even though '{cap}' was not declared "
                            f"in capabilities. {desc} is accessible despite not being advertised."
                        ),
                        evidence=f"URL: {server_url}\nMethod: {method}",
                        reasoning=(
                            "a non-empty JSON-RPC result to a method the server did not advertise "
                            "is strong, but a permissive server that returns a generic result for "
                            "any known method would look the same"
                        ),
                        signals={"method": method, "capability": cap},
                        references=self.references,
                        raw_data={"capability": cap, "method": method},
                        tier=ctx.tier,
                        evidence_ids=[exchange.id],
                    )
                )
            elif method in _NONSTANDARD_BY_METHOD:
                desc = _NONSTANDARD_BY_METHOD[method]
                verdicts.append(
                    Verdict(
                        severity="medium",
                        confidence=0.6,
                        discriminator=f"nonstandard-{method.replace('/', '-')}",
                        title=f"Non-standard method accepted: {method} returns data",
                        description=(
                            f"The MCP server responds to non-standard method '{method}' ({desc}). "
                            "This may expose administrative or debug functionality."
                        ),
                        evidence=f"URL: {server_url}\nMethod: {method}",
                        reasoning=(
                            "a JSON-RPC result to a non-spec method suggests a real handler, but a "
                            "catch-all route that answers 200 with a body to any path produces the "
                            "same signal without the method existing"
                        ),
                        signals={"method": method},
                        references=self.references,
                        raw_data={"method": method},
                        tier=ctx.tier,
                        evidence_ids=[exchange.id],
                    )
                )

        if not verdicts:
            probed = len(list(evidence))
            return [
                Verdict(
                    severity="info",
                    confidence=0.7,
                    discriminator="caps-clean",
                    title="Server correctly rejects requests for undeclared capabilities",
                    description="All probed undeclared capabilities and non-standard methods were rejected.",
                    evidence=f"URL: {server_url}\nMethods tested: {probed}",
                    reasoning=(
                        "the clean verdict is bounded by two fixed method tables; an undeclared "
                        "capability reachable by any method not in those tables would be missed"
                    ),
                    signals={"methods_tested": probed},
                    references=self.references,
                    tier=ctx.tier,
                    evidence_ids=[e.id for e in evidence],
                )
            ]

        return verdicts

    # ── The reading both halves share ────────────────────────────────

    def _accessible_standard(self, exchanges: list[Exchange]) -> list[dict]:
        out = []
        for exchange in exchanges:
            method = self._method_of(exchange)
            if method in _STANDARD_BY_METHOD and self._accessible(exchange):
                out.append({"capability": _STANDARD_BY_METHOD[method][0], "method": method})
        return out

    def _accessible_nonstandard(self, exchanges: list[Exchange]) -> list[dict]:
        out = []
        for exchange in exchanges:
            method = self._method_of(exchange)
            if method in _NONSTANDARD_BY_METHOD and self._accessible(exchange):
                out.append({"method": method, "description": _NONSTANDARD_BY_METHOD[method]})
        return out

    @staticmethod
    def _method_of(exchange: Exchange) -> str:
        try:
            return json.loads(exchange.request_body or "{}").get("method", "")
        except (json.JSONDecodeError, TypeError):
            return ""

    @staticmethod
    def _accessible(exchange: Exchange) -> bool:
        """A JSON-RPC method call that returned a non-empty result and no error."""
        if exchange.error or exchange.response_status not in (200, 201):
            return False
        if not exchange.response_body:
            return False
        try:
            data = json.loads(exchange.response_body)
        except (json.JSONDecodeError, TypeError):
            return False
        if not isinstance(data, dict):
            return False
        if "error" in data:
            # A JSON-RPC error means the server understood the protocol but
            # rejected the method — that is not "accessible".
            return False
        if "result" in data:
            return data["result"] not in (None, {}, [], "")
        return False
