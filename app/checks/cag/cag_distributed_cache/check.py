"""
app/checks/cag/distributed_cache.py - Distributed Cache Consistency

Detect multi-node cache topology and test replication consistency.

Attack vectors:
- Inconsistent replication: poisoning affects only some users
- Node identification via response headers
- Load balancer patterns reveal infrastructure topology

**Probe/grade.** The probe sends `TOPOLOGY_PROBE_COUNT`
identical requests and records each; `_detect_topology()` is the one parser both
halves call (§0.12), rebuilding the node observations off the recorded response
headers, bodies and `elapsed_ms` rather than a live measurement — so a re-grade
reaches the same topology from the same bytes.

**Fixed**: one candidate per endpoint, the discriminator
embeds the path, so the contract carries no map and `grade()` places the
severity (the `ai_model_info_check` pattern). Confidence is where the split
pays, because both signals are softer than they look: a distinct node header is
often a CDN or load-balancer id, not a separate *cache*; and "inconsistent
content across nodes" is indistinguishable from an LLM's own non-determinism at
this request count.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Headers that reveal cache node identity
NODE_HEADERS = [
    "x-cache-node",
    "x-served-by",
    "x-backend-server",
    "x-instance-id",
    "x-server-id",
    "via",
    "server",
    "x-amz-cf-id",
    "cf-ray",
]

# Number of requests to detect topology
TOPOLOGY_PROBE_COUNT = 10


class DistributedCacheCheck(ServiceIteratingCheck):
    """
    Detect multi-node cache topology and test replication consistency.

    Sends multiple identical requests and analyzes response headers to
    identify different cache nodes, then compares response content
    across nodes for consistency.
    """

    name = "cag_distributed_cache"
    description = "Detect multi-node cache topology and test replication consistency"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["distributed_cache_info"]
    service_types = ["ai", "api", "http"]

    reason = "Inconsistent cache replication means poisoning is harder to detect and only affects some users"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["topology detection", "replication analysis", "node fingerprinting"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        cag_endpoints = context.get("cag_endpoints", [])
        service_endpoints = [
            ep for ep in cag_endpoints if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        dist_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"dist-cache-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                        target=service,
                        target_url=url,
                    )
                    await self._probe_topology(client, url, scan_id, service.host, candidate)

                    topo_info = self._detect_topology(candidate.exchanges)
                    if topo_info:
                        dist_results.append(topo_info)
                        result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if dist_results:
            result.outputs["distributed_cache_info"] = dist_results

        return result

    async def _probe_topology(
        self, client: AsyncHttpClient, url: str, scan_id: str, host: str, candidate
    ) -> None:
        """Send the identical requests and record each."""
        # A stable query across the batch; the point is repeating the same one.
        payload = {"input": "distributed_cache_test", "query": "distributed_cache_test"}
        for _ in range(TOPOLOGY_PROBE_COUNT):
            try:
                resp = await client.post(url, json=payload, headers=JSON_HEADERS)
            except Exception:
                continue
            candidate.attach(
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

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        topo_info = self._detect_topology(list(evidence))
        if not topo_info:
            return []

        severity = self._determine_severity(topo_info)
        confidence, why = self._confidence(topo_info)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=None,
                title=self._build_title(topo_info),
                description=self._build_description(topo_info),
                evidence=self._build_evidence(topo_info),
                reasoning=why,
                signals={
                    "node_count": topo_info["node_count"],
                    "content_consistent": topo_info["content_consistent"],
                    "lb_pattern": topo_info["lb_pattern"],
                },
                references=self.references,
                raw_data=topo_info,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    @staticmethod
    def _confidence(topo_info: dict) -> tuple[float, str]:
        n = topo_info.get("node_count", 0)
        if not topo_info.get("content_consistent") and n > 1:
            return 0.4, (
                f"{n} distinct node ids answered with differing bodies — but at this request "
                "count differing text is exactly what a non-deterministic model produces on its "
                "own, so replication inconsistency is inferred, not shown, and the node ids "
                "themselves may be CDN/LB identifiers rather than separate caches"
            )
        if n > 1:
            return 0.55, (
                f"{n} distinct values appeared in {', '.join(NODE_HEADERS[:3])}-style headers; "
                "these are frequently CDN or load-balancer ids, so 'multiple cache nodes' reads "
                "more topology into a routing header than it proves"
            )
        return 0.4, (
            "the only signal is node-identity headers, and a single value across the batch is "
            "as consistent with one node as with a sticky balancer hiding several"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _detect_topology(self, exchanges: list[Exchange]) -> dict | None:
        """Rebuild the topology reading off the recorded requests."""
        node_observations = []
        response_bodies = []

        for index, exchange in enumerate(self._probes(exchanges)):
            if exchange.error:
                continue
            node_id = self._extract_node_id(exchange.response_headers or {})
            response_bodies.append(exchange.response_body or "")
            node_observations.append(
                {
                    "request_index": index,
                    "node_id": node_id,
                    "elapsed_ms": round(exchange.elapsed_ms, 2) if exchange.elapsed_ms else 0,
                    "status_code": exchange.response_status,
                }
            )

        if len(node_observations) < 3:
            return None

        unique_nodes = {obs["node_id"] for obs in node_observations if obs["node_id"]}
        unique_responses = set(response_bodies)
        content_consistent = len(unique_responses) <= 1
        lb_pattern = self._detect_lb_pattern(node_observations)

        if not unique_nodes and content_consistent:
            return None

        return {
            "url": self._probes(exchanges)[0].request_url,
            "total_requests": len(node_observations),
            "unique_nodes": list(unique_nodes),
            "node_count": len(unique_nodes),
            "content_consistent": content_consistent,
            "unique_responses": len(unique_responses),
            "lb_pattern": lb_pattern,
            "node_observations": node_observations,
        }

    @staticmethod
    def _probes(exchanges: list[Exchange]) -> list[Exchange]:
        return [e for e in exchanges if e.request_method == "POST"]

    def _extract_node_id(self, headers: dict) -> str | None:
        """Extract node identifier from response headers."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header in NODE_HEADERS:
            value = headers_lower.get(header)
            if value:
                return f"{header}:{value}"

        return None

    def _detect_lb_pattern(self, observations: list[dict]) -> str:
        """Detect load balancing pattern from node observations."""
        node_ids = [obs["node_id"] for obs in observations if obs["node_id"]]

        if not node_ids:
            return "unknown"

        unique = list(dict.fromkeys(node_ids))  # Preserve order, deduplicate

        if len(unique) == 1:
            return "sticky"

        # Check for round-robin (alternating pattern)
        if len(unique) >= 2:
            is_round_robin = True
            for i in range(len(node_ids) - 1):
                if node_ids[i] == node_ids[i + 1]:
                    is_round_robin = False
                    break
            if is_round_robin:
                return "round_robin"

        return "random"

    def _determine_severity(self, topo_info: dict) -> str:
        """Determine observation severity."""
        if not topo_info.get("content_consistent") and topo_info.get("node_count", 0) > 1:
            return "medium"
        if topo_info.get("node_count", 0) > 1:
            return "low"
        return "info"

    def _build_title(self, topo_info: dict) -> str:
        """Build observation title."""
        n = topo_info.get("node_count", 0)

        if not topo_info.get("content_consistent") and n > 1:
            return f"Cache replication inconsistency: different content served by {n} nodes"
        if n > 1:
            return f"Multiple cache nodes detected: {n} nodes identified from response headers"
        return "Single cache node or consistent replication"

    def _build_description(self, topo_info: dict) -> str:
        """Build observation description."""
        n = topo_info.get("node_count", 0)

        if not topo_info.get("content_consistent") and n > 1:
            return (
                f"Detected {n} unique cache nodes with inconsistent response content. "
                f"Cache replication inconsistency means a poisoned entry on one node may not "
                f"be visible on others, making poisoning harder to detect but also meaning "
                f"only a subset of users are affected."
            )
        if n > 1:
            pattern = topo_info.get("lb_pattern", "unknown")
            return (
                f"Detected {n} unique cache nodes with consistent content. "
                f"Load balancing pattern: {pattern}. Node identifiers visible in headers."
            )
        return "No multi-node topology detected."

    def _build_evidence(self, topo_info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Total requests: {topo_info['total_requests']}",
            f"Unique nodes: {topo_info['node_count']}",
            f"Content consistent: {topo_info['content_consistent']}",
            f"LB pattern: {topo_info.get('lb_pattern', 'unknown')}",
        ]

        for node in topo_info.get("unique_nodes", [])[:5]:
            lines.append(f"  Node: {node}")

        return "\n".join(lines)
