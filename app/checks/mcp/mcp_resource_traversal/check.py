"""
app/checks/mcp/resource_traversal.py - MCP Resource URI Traversal

Tests MCP resources for path traversal and SSRF via resource URIs.
Sends resources/read with crafted URIs to probe for unauthorized access.

Safety: read-only probes, no destructive payloads, response capped.

**Probe/grade.** The probe sends one `resources/read` per
crafted URI, records each via `exchange_from_response`, and hands one candidate
per server to the grader. `grade()` re-reads each recorded exchange, recovers
which payload produced it from the request body's `params.uri` (§0.16 — never
positional, never the discriminator), and places the severity; when no dangerous
answer is found it emits the single `resource-safe` verdict. `_probe_result()`
is the one parser both halves call (§0.12).

**Fixed**: the discriminators are a closed set — the payload
category crossed with the attack type — so the contract carries the full
`observations:` map at each entry's severity. Confidence is where the split pays:
a file-content marker can ride in an error message that quotes the path back, and
a non-standard protocol answered with a body is not-rejected, not shown to have
smuggled anything.

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/server/resources/
  CWE-22 Path Traversal
  CWE-918 SSRF
"""

import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.checks.mcp.invocation_safety import cap_response
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

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

# uri -> (category, attack_type), for read-back at grade time.
_PAYLOAD_INDEX: dict[str, tuple[str, str]] = {}
for _uri, _atk, _desc in TRAVERSAL_PAYLOADS:
    _PAYLOAD_INDEX[_uri] = ("traversal", _atk)
for _uri, _atk, _desc in SSRF_PAYLOADS:
    _PAYLOAD_INDEX[_uri] = ("ssrf", _atk)
for _uri, _atk, _desc in PROTOCOL_PAYLOADS:
    _PAYLOAD_INDEX[_uri] = ("protocol", _atk)


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

    intrusive = True

    reason = "MCP resources accessed by URI may be vulnerable to path traversal and SSRF"
    references = [
        "MCP Specification - Resources - https://spec.modelcontextprotocol.io/specification/server/resources/",
        "CWE-22 Path Traversal",
        "CWE-918 Server-Side Request Forgery",
    ]
    techniques = ["path traversal", "SSRF", "protocol smuggling"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = context.get("mcp_servers", [])
        scan_id = context.get("scan_id") or ""
        traversal_results = []

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
                    # Enumerate resources first (recorded, not graded).
                    await self._enumerate_resources(client, server_url, host, scan_id)

                    for uri, _cat, _atk in TRAVERSAL_PAYLOADS + SSRF_PAYLOADS + PROTOCOL_PAYLOADS:
                        exchange = await self._probe_resource(
                            client, server_url, uri, host, scan_id
                        )
                        exchanges.append(exchange)
                        pr = self._probe_result(exchange)
                        if pr is not None:
                            traversal_results.append(
                                {
                                    "tool": f"resources/read:{pr['attack_type']}",
                                    "payload": {"uri": uri},
                                    "response_status": pr["status"],
                                    "response_preview": cap_response(pr["body"]),
                                    "safe": True,
                                }
                            )

            except Exception as e:
                result.errors.append(f"Resource traversal on {server_url}: {e}")
                continue

            candidate = self.create_candidate(host=host)
            for exchange in exchanges:
                candidate.attach(exchange)
            result.candidates.append(candidate)

        if traversal_results:
            result.outputs["mcp_resource_traversal_results"] = traversal_results

        return result

    async def _enumerate_resources(self, client, server_url: str, host: str, scan_id: str) -> None:
        """Enumerate available resources via resources/list (recorded for the corpus)."""
        payload = {"jsonrpc": "2.0", "method": "resources/list", "id": 1}
        resp = await client.post(server_url, json=payload, headers=JSON_HEADERS)
        exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="POST",
            request_headers=JSON_HEADERS,
            request_json=payload,
        )

    async def _probe_resource(
        self, client, server_url: str, uri: str, host: str, scan_id: str
    ) -> Exchange:
        """Send resources/read with a crafted URI and record the exchange."""
        payload = {"jsonrpc": "2.0", "method": "resources/read", "params": {"uri": uri}, "id": 1}
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
        # Several payloads share an attack type (passwd and hosts are both
        # `path_traversal`), and the discriminator is category x attack type, so
        # hits are grouped and each discriminator yields ONE verdict naming every
        # URI. One verdict per payload minted the same observation id twice.
        groups: dict[str, list[tuple[dict, Exchange]]] = {}
        for exchange in evidence:
            pr = self._probe_result(exchange)
            if pr is None:
                continue
            discriminator = self._classify(pr)
            if discriminator is not None:
                groups.setdefault(discriminator, []).append((pr, exchange))

        verdicts = [
            self._verdict_for(discriminator, hits, ctx) for discriminator, hits in groups.items()
        ]

        if not verdicts:
            # Only emit the safe verdict when this candidate actually probed
            # (a resources/read exchange is present), matching the pre-split
            # per-server fallback.
            probed = [e for e in evidence if self._uri_of(e) is not None]
            if probed:
                verdicts.append(
                    Verdict(
                        severity="info",
                        confidence=0.6,
                        discriminator="resource-safe",
                        title="Resource URI validation enforced (traversal attempts rejected)",
                        description="MCP resource URIs are properly validated against traversal and SSRF.",
                        evidence=f"Payloads tested: {len(TRAVERSAL_PAYLOADS) + len(SSRF_PAYLOADS) + len(PROTOCOL_PAYLOADS)}",
                        reasoning=(
                            "no payload returned file content, a leaked path or an accepted "
                            "protocol; the absence is bounded by the fixed payload list, so a "
                            "traversal expressed a way not tried would read as safe"
                        ),
                        tier=ctx.tier,
                        evidence_ids=[e.id for e in probed],
                    )
                )
        return verdicts

    def _classify(self, pr: dict) -> str | None:
        """The discriminator one payload's reading earns, or None when it earns none."""
        category = pr["category"]
        atk = pr["attack_type"]
        body = pr["body"]

        if category == "traversal":
            if pr["success"] and pr["has_content"] and self._looks_like_file_content(body):
                return f"traversal-{atk}"
            if pr.get("error_leaks_path"):
                return f"traversal-leak-{atk}"
            return None

        if category == "ssrf":
            if pr["success"] and pr["has_content"] and self._looks_like_ssrf_content(body, atk):
                return f"ssrf-{atk}"
            return None

        # protocol smuggling
        if pr["success"] and pr["has_content"]:
            return f"protocol-{atk}"
        return None

    def _verdict_for(
        self, discriminator: str, hits: list[tuple[dict, Exchange]], ctx: GradeContext
    ) -> Verdict:
        """One verdict for every payload that earned `discriminator`.

        With a single hit the title, description and evidence read exactly as
        they did when each payload had a verdict of its own.
        """
        uris = [pr["uri"] for pr, _ in hits]
        shown = ", ".join(uris)
        ids = [exchange.id for _, exchange in hits]
        first_body = cap_response(hits[0][0]["body"])

        def evidence(label: str) -> str:
            return "\n\n".join(
                f"URI: {pr['uri']}\n{label}: {cap_response(pr['body'])[:300]}" for pr, _ in hits
            )

        if discriminator.startswith("traversal-leak-"):
            return Verdict(
                severity="medium",
                confidence=0.6,
                discriminator=discriminator,
                title="Resource traversal blocked but error leaks file path",
                description=f"Error message reveals internal path structure for URI: {shown}",
                evidence=evidence("Error"),
                reasoning=(
                    "the read was refused, and the confidence rests on an error string "
                    "containing an absolute path prefix; a message that merely echoes the "
                    "attacker-supplied URI would match the same prefixes"
                ),
                raw_data={"uri": uris[0], "uris": uris, "body": first_body},
                tier=ctx.tier,
                evidence_ids=ids,
            )

        if discriminator.startswith("traversal-"):
            return Verdict(
                severity="critical",
                confidence=0.7,
                discriminator=discriminator,
                title=f"Resource path traversal: {shown} returned file contents",
                description=f"The MCP resource endpoint returned actual file contents for traversal URI: {shown}",
                evidence=evidence("Response"),
                reasoning=(
                    "the response carries a file-content marker (root:, /bin/bash, a hosts "
                    "entry), but an error message that quotes the requested path back, or a "
                    "decoy file, can carry the same marker without a real read"
                ),
                raw_data={"uri": uris[0], "uris": uris, "body": first_body},
                tier=ctx.tier,
                evidence_ids=ids,
            )

        if discriminator.startswith("ssrf-"):
            return Verdict(
                severity="critical",
                confidence=0.65,
                discriminator=discriminator,
                title=f"SSRF via MCP resource: {shown} returned internal data",
                description=f"The MCP resource endpoint fetched an internal URL: {shown}",
                evidence=evidence("Response"),
                reasoning=(
                    "the response contains a marker for the targeted internal service, but "
                    "those keywords (version, metadata, cluster_name) also appear in generic "
                    "pages, so a fetch that reached something benign can look internal"
                ),
                raw_data={"uri": uris[0], "uris": uris, "body": first_body},
                tier=ctx.tier,
                evidence_ids=ids,
            )

        # protocol smuggling
        schemes = ", ".join(dict.fromkeys(f"{uri.split(':')[0]}://" for uri in uris))
        return Verdict(
            severity="high",
            confidence=0.5,
            discriminator=discriminator,
            title=f"Resource URI accepts {schemes} protocol",
            description=f"The MCP resource endpoint accepted a non-standard protocol URI: {shown}",
            evidence=evidence("Response"),
            reasoning=(
                "the endpoint returned a body for a gopher/dict URI, which is not-rejected, "
                "not shown to have smuggled a payload — any 200 with content passes this bar, "
                "and no downstream service is observed acting on it"
            ),
            raw_data={"uri": uris[0], "uris": uris},
            tier=ctx.tier,
            evidence_ids=ids,
        )

    # ── The parser both halves share ─────────────────────────────────

    @staticmethod
    def _uri_of(exchange: Exchange) -> str | None:
        """The `params.uri` of a resources/read request, or None for anything else."""
        try:
            body = json.loads(exchange.request_body or "{}")
        except json.JSONDecodeError:
            return None
        if body.get("method") != "resources/read":
            return None
        return body.get("params", {}).get("uri")

    def _probe_result(self, exchange: Exchange) -> dict | None:
        """The original `_probe_resource` reading, rebuilt off one recorded exchange.

        `None` for a non-read exchange, an unknown URI, or a transport error —
        the cases the pre-split code produced no observation for.
        """
        uri = self._uri_of(exchange)
        if uri is None or uri not in _PAYLOAD_INDEX:
            return None
        category, attack_type = _PAYLOAD_INDEX[uri]

        pr = {
            "uri": uri,
            "category": category,
            "attack_type": attack_type,
            "success": False,
            "has_content": False,
            "body": exchange.response_body or "",
            "status": exchange.response_status if not exchange.error else None,
            "error_leaks_path": False,
        }

        if exchange.error:
            return pr

        if exchange.response_status == 200 and exchange.response_body:
            try:
                data = json.loads(exchange.response_body)
                if isinstance(data, dict) and "error" in data:
                    error_msg = str(data["error"])
                    if any(p in error_msg for p in ["/opt/", "/var/", "/home/", "C:\\", "/etc/"]):
                        pr["error_leaks_path"] = True
                        pr["has_content"] = True
                    return pr

                result_data = data.get("result", data)
                if isinstance(result_data, dict) and "contents" in result_data:
                    contents = result_data["contents"]
                    if contents and isinstance(contents, list) and len(contents) > 0:
                        pr["success"] = True
                        pr["has_content"] = True
                        pr["body"] = str(contents[0])
                elif result_data and str(result_data) not in ("{}", "[]", "None", ""):
                    pr["success"] = True
                    pr["has_content"] = True
            except (json.JSONDecodeError, TypeError):
                if len(exchange.response_body) > 10:
                    pr["success"] = True
                    pr["has_content"] = True

        return pr

    def _looks_like_file_content(self, body: str) -> bool:
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
