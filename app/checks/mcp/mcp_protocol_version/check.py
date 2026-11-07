"""
app/checks/mcp/protocol_version.py - MCP Protocol Version Probing

Tests older MCP protocol versions for downgrade vulnerabilities.
Checks if the server accepts older protocol versions with potentially
weaker security.

**Probe/grade.** The probe sends one `initialize` POST per
known protocol version, records each, and hands them over as one candidate per
server (§0.15). `_reading()` is the one parser both halves call (§0.12): each
response is paired with the version it answered by reading `protocolVersion`
back off the recorded *request* body (§0.16), never a remembered list, so a
re-grade reconstructs the same accepted/rejected split. `grade()` then applies
the downgrade logic.

**Fixed**: the two discriminators are a closed set, so the
contract carries the full `observations:` map at each floor —
`protocol-downgrade` at `low` (it rises to `medium` only when the old version
sheds capabilities) and `protocol-current` at `info`. Confidence is where the
split pays: a server accepting an old version string is **not-rejected, not
downgraded** — it returns its own `protocolVersion` and may ignore the field
entirely.

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

# Known MCP protocol versions (oldest to newest)
PROTOCOL_VERSIONS = [
    ("2024-01-01", "Early draft"),
    ("2024-06-01", "Pre-release"),
    ("2024-10-07", "Release candidate"),
    ("2024-11-05", "Current stable"),
    ("2025-03-26", "Latest"),
]

_VERSION_DESC = dict(PROTOCOL_VERSIONS)


class MCPProtocolVersionCheck(BaseCheck):
    """
    Test MCP server protocol version handling.

    Probes with older protocol versions to check for downgrade
    acceptance and capability differences.
    """

    name = "mcp_protocol_version"
    description = "Test MCP server for protocol version downgrade vulnerabilities"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_protocol_versions"]
    service_types = ["ai", "api", "http"]

    reason = "Older MCP protocol versions may have weaker security or missing capabilities"
    references = [
        "MCP Specification - https://modelcontextprotocol.io/specification",
    ]
    techniques = ["protocol downgrade", "version probing"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        mcp_servers = context.get("mcp_servers", [])
        version_results = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")

            if not server_url:
                continue

            exchanges: list[Exchange] = []
            try:
                async with AsyncHttpClient(cfg) as client:
                    for version, _desc in PROTOCOL_VERSIONS:
                        payload = {
                            "jsonrpc": "2.0",
                            "method": "initialize",
                            "params": {
                                "protocolVersion": version,
                                "capabilities": {},
                                "clientInfo": {
                                    "name": "chainsmith-version-probe",
                                    "version": "1.0",
                                },
                            },
                            "id": 1,
                        }
                        resp = await client.post(server_url, json=payload, headers=JSON_HEADERS)
                        exchanges.append(
                            exchange_from_response(
                                resp,
                                check_name=self.name,
                                scan_id=scan_id,
                                host=host,
                                method="POST",
                                request_headers=JSON_HEADERS,
                                request_json=payload,
                            )
                        )
            except Exception as e:
                result.errors.append(f"Protocol version probe on {server_url}: {e}")
                continue

            accepted, rejected = self._reading(exchanges)
            version_results.append(
                {
                    "url": server_url,
                    "host": host,
                    "accepted": accepted,
                    "rejected": rejected,
                }
            )

            candidate = self.create_candidate(host=host, target_url=server_url)
            for exchange in exchanges:
                candidate.attach(exchange)
            result.candidates.append(candidate)

        if version_results:
            result.outputs["mcp_protocol_versions"] = version_results

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        exchanges = list(evidence)
        if not exchanges:
            return []

        accepted, rejected = self._reading(exchanges)
        server_url = ctx.target_url or ""
        version_info = {
            "url": server_url,
            "host": ctx.host,
            "accepted": accepted,
            "rejected": rejected,
        }

        if len(accepted) > 1:
            oldest = accepted[0]
            newest = accepted[-1]
            if oldest["requested"] == newest["requested"]:
                return []

            oldest_caps = set(oldest.get("capabilities", []))
            newest_caps = set(newest.get("capabilities", []))
            missing_in_old = newest_caps - oldest_caps
            severity = "medium" if missing_in_old else "low"

            if missing_in_old:
                confidence = 0.6
                why = (
                    "the old version was accepted and came back with fewer capabilities than "
                    "the newest, so a downgrade has a concrete effect; still, the server chose "
                    "what to return and nothing was exercised over the reduced surface"
                )
            else:
                confidence = 0.45
                why = (
                    "the server returned 200 to an old protocolVersion string, but that is "
                    "not-rejected, not downgraded — it answered with its own version and may "
                    "ignore the requested field entirely; capabilities were identical"
                )

            return [
                Verdict(
                    severity=severity,
                    confidence=confidence,
                    discriminator="protocol-downgrade",
                    title=f"MCP server supports protocol downgrade: accepted version {oldest['requested']}",
                    description=(
                        f"Server accepted protocol version {oldest['requested']} ({oldest['description']}). "
                        f"Latest accepted: {newest['requested']}. "
                        + (
                            f"Older version missing capabilities: {', '.join(missing_in_old)}"
                            if missing_in_old
                            else ""
                        )
                    ),
                    evidence=(
                        f"Accepted versions: {', '.join(v['requested'] for v in accepted)}\n"
                        f"Oldest caps: {', '.join(oldest_caps) or 'none'}\n"
                        f"Newest caps: {', '.join(newest_caps) or 'none'}"
                    ),
                    reasoning=why,
                    signals={
                        "accepted": [v["requested"] for v in accepted],
                        "missing_in_old": sorted(missing_in_old),
                    },
                    raw_data=version_info,
                    tier=ctx.tier,
                    evidence_ids=[e.id for e in exchanges],
                )
            ]

        if len(accepted) == 1:
            return [
                Verdict(
                    severity="info",
                    confidence=0.7,
                    discriminator="protocol-current",
                    title="Server only accepts current protocol version",
                    description=f"MCP server only accepted version {accepted[0]['requested']}.",
                    evidence=f"Accepted: {accepted[0]['requested']}\nRejected: {', '.join(rejected)}",
                    reasoning=(
                        "only one version negotiated successfully; the negative — that the "
                        "others are refused — is bounded by the fixed version list probed, not "
                        "every version that could exist"
                    ),
                    signals={"rejected": rejected},
                    raw_data=version_info,
                    tier=ctx.tier,
                    evidence_ids=[e.id for e in exchanges],
                )
            ]

        return []

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> tuple[list[dict], list[str]]:
        """Rebuild the accepted / rejected split off the recorded exchanges.

        Each response is paired with the version it answered by reading the
        `protocolVersion` back off the request body, so ordering follows the
        recorded probe rather than any remembered list.
        """
        accepted: list[dict] = []
        rejected: list[str] = []

        for exchange in exchanges:
            version = self._requested_version(exchange)
            if version is None:
                continue

            status = exchange.response_status
            if exchange.error or status not in (200, 201):
                rejected.append(version)
                continue

            try:
                data = json.loads(exchange.response_body or "{}")
                if isinstance(data, dict) and "error" not in data:
                    rpc_result = data.get("result", {})
                    server_version = rpc_result.get("protocolVersion", "")
                    caps = rpc_result.get("capabilities", {})
                    accepted.append(
                        {
                            "requested": version,
                            "server_responded": server_version,
                            "capabilities": list(caps.keys()) if isinstance(caps, dict) else [],
                            "description": _VERSION_DESC.get(version, ""),
                        }
                    )
                else:
                    rejected.append(version)
            except (json.JSONDecodeError, TypeError):
                rejected.append(version)

        return accepted, rejected

    @staticmethod
    def _requested_version(exchange: Exchange) -> str | None:
        """The protocolVersion this request asked for, off its recorded body."""
        try:
            body = json.loads(exchange.request_body or "{}")
        except (json.JSONDecodeError, TypeError):
            return None
        version = body.get("params", {}).get("protocolVersion")
        return version if isinstance(version, str) and version else None
