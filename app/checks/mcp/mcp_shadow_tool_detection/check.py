"""
app/checks/mcp/shadow_tool_detection.py - Shadow Tool Detection

Tests whether MCP tool names can be overwritten or collided with,
enabling attackers to shadow legitimate tools with malicious replacements.

Detection tests (safe, non-destructive):
1. Tool namespace analysis (flat vs prefixed names)
2. Common name collision risk
3. tools/list_changed notification acceptance
4. Re-registration via duplicate initialize

Operates primarily on already-enumerated data, with light protocol probing.

**Probe/grade.** The probe records the two things its
verdicts read: the enumerated tool names, as a `local` exchange (the
`network_geoip`/`schema_leakage` precedent, §0.12), and each protocol probe it
sends (`notifications/tools/list_changed`, two `initialize`) via
`exchange_from_response`. `grade()` re-reads all of them — namespace and
collision analysis off the `local` names, the protocol verdicts off the recorded
POST responses, the two `initialize` requests told apart by recorded order
(§0.15). `_findings_from()` is the one analysis both halves call.

**Fixed**: the discriminators are a closed five-value set,
so the contract carries the full `observations:` map at each entry's severity.
Confidence is where the split pays: a 2xx to a `list_changed` notification is
not-rejected, not honoured — nothing reads the tool table back to show it
changed — and the flat-naming / collision risks require a second,
attacker-controlled server that is not observed here.

References:
  https://modelcontextprotocol.io/specification
  MITRE ATLAS - AML.T0051 LLM Plugin Compromise
"""

import json
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Common MCP tool names prone to collision in multi-server setups
COMMON_TOOL_NAMES = {
    "read_file",
    "write_file",
    "search",
    "fetch",
    "browse",
    "execute",
    "get_weather",
    "send_email",
    "query",
    "list_files",
    "create_file",
    "delete_file",
    "http_request",
    "run_command",
    "get_url",
    "read",
    "write",
    "get",
    "set",
    "list",
    "create",
    "delete",
    "update",
    "find",
    "open",
    "close",
    "send",
    "receive",
}


class ShadowToolDetectionCheck(BaseCheck):
    """
    Detect shadow tool attack susceptibility in MCP servers.

    Checks whether tool names use namespacing, whether common names
    create collision risk, and whether the server accepts unsolicited
    tool re-registration attempts.
    """

    name = "mcp_shadow_tool_detection"
    description = "Detect MCP shadow tool attack susceptibility"

    conditions = [CheckCondition("mcp_tools", "truthy")]
    produces = ["mcp_shadow_tool_risk"]
    service_types = ["ai", "api", "http"]

    reason = "In multi-server MCP setups, tool name collisions allow attackers to shadow legitimate tools with malicious replacements"
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
        "MITRE ATLAS - AML.T0051 LLM Plugin Compromise",
    ]
    techniques = ["namespace analysis", "protocol probing", "collision detection"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_tools = context.get("mcp_tools", [])
        mcp_servers = context.get("mcp_servers", [])

        if not mcp_tools:
            return result

        scan_id = context.get("scan_id") or ""
        host = mcp_tools[0].get("service_host", "unknown")
        tool_names = [t.get("name", "") for t in mcp_tools]

        exchanges: list[Exchange] = [
            capture.record_exchange(
                "local",
                host,
                request_body="mcp_shadow_tool_detection tool_names",
                request_headers={"source": "mcp_tools"},
                response_body=json.dumps(tool_names),
            )
        ]

        if mcp_servers:
            cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
            try:
                async with AsyncHttpClient(cfg) as client:
                    for server in mcp_servers:
                        server_url = server.get("url", "")
                        if not server_url:
                            continue
                        exchanges.extend(
                            await self._probe_server(client, server_url, host, scan_id)
                        )
            except Exception as e:
                result.errors.append(f"Shadow tool protocol test: {e}")

        candidate = self.create_candidate(host=host)
        for exchange in exchanges:
            candidate.attach(exchange)
        result.candidates.append(candidate)

        _, shadow_risk = self._findings_from(exchanges)
        result.outputs["mcp_shadow_tool_risk"] = shadow_risk
        return result

    async def _probe_server(
        self, client: AsyncHttpClient, server_url: str, host: str, scan_id: str
    ) -> list[Exchange]:
        """Record the three protocol probes for one server, in the order
        `_findings_from` re-reads them (notification, then the two initialize)."""
        recorded: list[Exchange] = []

        notif = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
        resp = await client.post(server_url, json=notif, headers=JSON_HEADERS)
        recorded.append(self._exchange(resp, host, scan_id, notif))

        init_a = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": True}},
                "clientInfo": {"name": "chainsmith-shadow-a", "version": "1.0"},
            },
            "id": 1,
        }
        resp1 = await client.post(server_url, json=init_a, headers=JSON_HEADERS)
        exchange1 = self._exchange(resp1, host, scan_id, init_a)
        recorded.append(exchange1)

        # The second initialize is only sent when the first is accepted, matching
        # the pre-split control flow.
        if not resp1.error and resp1.status_code in (200, 201):
            init_b = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": True}},
                    "clientInfo": {"name": "chainsmith-shadow-b", "version": "2.0"},
                },
                "id": 2,
            }
            resp2 = await client.post(server_url, json=init_b, headers=JSON_HEADERS)
            recorded.append(self._exchange(resp2, host, scan_id, init_b))

        return recorded

    def _exchange(self, resp, host: str, scan_id: str, payload: dict) -> Exchange:
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
        findings, _ = self._findings_from(list(evidence))
        verdicts: list[Verdict] = []
        for finding in findings:
            confidence, why = self._confidence(finding)
            verdicts.append(
                Verdict(
                    severity=finding["severity"],
                    confidence=confidence,
                    discriminator=finding["discriminator"],
                    title=finding["title"],
                    description=finding["description"],
                    evidence=finding["evidence"],
                    reasoning=why,
                    signals={"kind": finding["discriminator"]},
                    raw_data=finding.get("raw_data"),
                    tier=ctx.tier,
                    evidence_ids=[finding["evidence_id"]],
                )
            )
        return verdicts

    @staticmethod
    def _confidence(finding: dict) -> tuple[float, str]:
        disc = finding["discriminator"]
        if disc == "namespace-flat":
            return 0.6, (
                "the tools genuinely use flat names, but the attack needs a second, "
                "attacker-controlled MCP server registering colliding names — that server "
                "is not observed, so this is structural exposure, not a demonstrated shadow"
            )
        if disc == "namespace-safe":
            return 0.7, (
                "every tool name carries a namespace prefix; the judgement is bounded by a "
                "fixed set of prefix markers ('/', '::', a dotted path), so an unusual scheme "
                "could be misread as flat"
            )
        if disc == "name-collision":
            return 0.5, (
                "the names match a hand-curated list of common MCP tool names, and a collision "
                "only bites in a multi-server setup with a colluding server; a match here is a "
                "risk indicator, not an attack"
            )
        if disc == "list-changed-accepted":
            return 0.4, (
                "the server returned 2xx to a list_changed notification, which is not-rejected, "
                "not honoured — nothing reads the tool table back to show it actually changed, "
                "and a server that accepts and ignores unknown notifications answers 2xx too"
            )
        if disc == "reinitialize-accepted":
            return 0.45, (
                "a second initialize was accepted, but many servers accept re-initialize "
                "harmlessly; no tool was shown replaced, so accepted is not exploited"
            )
        return 0.5, "rule-tier judgement"

    # ── The analysis both halves share ───────────────────────────────

    def _findings_from(self, exchanges: list[Exchange]) -> tuple[list[dict], dict]:
        """Findings (observation-shaped, in emission order) plus the
        `mcp_shadow_tool_risk` output dict, from the recorded exchanges."""
        findings: list[dict] = []
        shadow_risk: dict = {
            "namespace_analysis": {},
            "collision_candidates": [],
            "notification_tests": {},
        }

        local = next((e for e in exchanges if e.protocol == "local"), None)
        tool_names = self._names_from(local) if local else []
        local_id = local.id if local else ""

        # Test 1: namespacing
        finding, analysis = self._namespace_finding(tool_names, local_id)
        shadow_risk["namespace_analysis"] = analysis
        if finding:
            findings.append(finding)

        # Test 2: common-name collisions
        finding, collisions = self._collision_finding(tool_names, local_id)
        shadow_risk["collision_candidates"] = collisions
        if finding:
            findings.append(finding)

        # Test 3/4: protocol probes, grouped per server URL in recorded order
        by_url: dict[str, list[Exchange]] = {}
        for exchange in exchanges:
            if exchange.protocol == "local":
                continue
            by_url.setdefault(exchange.request_url or "", []).append(exchange)

        for url, server_exchanges in by_url.items():
            notif = next(
                (
                    e
                    for e in server_exchanges
                    if self._method_of(e) == "notifications/tools/list_changed"
                ),
                None,
            )
            inits = [e for e in server_exchanges if self._method_of(e) == "initialize"]

            if notif is not None:
                accepted = self._accepted(notif, (200, 202, 204))
                shadow_risk["notification_tests"]["list_changed"] = {
                    "accepted": accepted,
                    "status": notif.response_status if not notif.error else None,
                }
                if accepted:
                    findings.append(
                        {
                            "severity": "high",
                            "discriminator": "list-changed-accepted",
                            "title": "Server accepts client notifications/tools/list_changed",
                            "description": (
                                "The MCP server accepted a tools/list_changed notification "
                                "from the client. This may allow a client to influence the "
                                "server's tool registration state."
                            ),
                            "evidence": f"URL: {url}\nMethod: notifications/tools/list_changed\nStatus: {notif.response_status}",
                            "raw_data": {"status": notif.response_status},
                            "evidence_id": notif.id,
                        }
                    )

            if len(inits) >= 2:
                resp1, resp2 = inits[0], inits[1]
                if self._accepted(resp1, (200, 201)) and self._accepted(resp2, (200, 201)):
                    shadow_risk["notification_tests"]["reinitialize"] = {
                        "accepted": True,
                        "status": resp2.response_status,
                    }
                    findings.append(
                        {
                            "severity": "low",
                            "discriminator": "reinitialize-accepted",
                            "title": "MCP server accepts tool re-registration: duplicate initialize accepted",
                            "description": (
                                "The MCP server accepted a second initialize request with different "
                                "clientInfo. This indicates the server may not enforce single-session "
                                "semantics, potentially allowing tool replacement."
                            ),
                            "evidence": f"First init: status {resp1.response_status}\nSecond init: status {resp2.response_status}",
                            "raw_data": {
                                "first_status": resp1.response_status,
                                "second_status": resp2.response_status,
                            },
                            "evidence_id": resp2.id,
                        }
                    )

        return findings, shadow_risk

    @staticmethod
    def _names_from(exchange: Exchange) -> list[str]:
        if not exchange.response_body:
            return []
        try:
            names = json.loads(exchange.response_body)
        except json.JSONDecodeError:
            return []
        return names if isinstance(names, list) else []

    @staticmethod
    def _method_of(exchange: Exchange) -> str:
        try:
            return json.loads(exchange.request_body or "{}").get("method", "")
        except json.JSONDecodeError:
            return ""

    @staticmethod
    def _accepted(exchange: Exchange, ok: tuple[int, ...]) -> bool:
        return not exchange.error and exchange.response_status in ok

    def _namespace_finding(
        self, tool_names: list[str], evidence_id: str
    ) -> tuple[dict | None, dict]:
        namespaced = []
        flat = []
        for name in tool_names:
            if "/" in name or "::" in name or (name.count(".") >= 2):
                namespaced.append(name)
            else:
                flat.append(name)

        analysis = {
            "total_tools": len(tool_names),
            "namespaced": len(namespaced),
            "flat": len(flat),
            "namespaced_names": namespaced[:10],
            "flat_names": flat[:10],
        }

        if namespaced and not flat:
            return (
                {
                    "severity": "info",
                    "discriminator": "namespace-safe",
                    "title": "Tools are namespaced (shadow tool resistant)",
                    "description": (
                        f"All {len(tool_names)} tools use namespaced naming "
                        f"(e.g., '{namespaced[0]}'). This makes shadow tool attacks "
                        "significantly harder in multi-server configurations."
                    ),
                    "evidence": f"Namespaced tools: {', '.join(namespaced[:5])}",
                    "raw_data": None,
                    "evidence_id": evidence_id,
                },
                analysis,
            )
        if flat:
            return (
                {
                    "severity": "medium",
                    "discriminator": "namespace-flat",
                    "title": "MCP tools use flat naming (no namespace prefix) — vulnerable to shadow tool attacks",
                    "description": (
                        f"{len(flat)} of {len(tool_names)} tools use flat (unprefixed) names. "
                        "In multi-server MCP configurations, an attacker-controlled server "
                        "could register tools with the same names, causing the client to "
                        "invoke the attacker's version instead."
                    ),
                    "evidence": f"Flat tool names: {', '.join(flat[:10])}",
                    "raw_data": {"flat_names": flat, "namespaced_names": namespaced},
                    "evidence_id": evidence_id,
                },
                analysis,
            )
        return None, analysis

    def _collision_finding(
        self, tool_names: list[str], evidence_id: str
    ) -> tuple[dict | None, list]:
        lowered = {name.lower() for name in tool_names}
        collisions = sorted(lowered & COMMON_TOOL_NAMES)

        if collisions:
            return (
                {
                    "severity": "low",
                    "discriminator": "name-collision",
                    "title": f"Collision-risk tool names detected: {len(collisions)} match common MCP names",
                    "description": (
                        f"The following tool names match commonly-used MCP tool names: "
                        f"{', '.join(collisions)}. "
                        "In multi-server configurations, another server registering "
                        "the same names would create a shadow tool collision."
                    ),
                    "evidence": f"Collision candidates: {', '.join(collisions)}",
                    "raw_data": {"collisions": collisions},
                    "evidence_id": evidence_id,
                },
                collisions,
            )
        return None, collisions
