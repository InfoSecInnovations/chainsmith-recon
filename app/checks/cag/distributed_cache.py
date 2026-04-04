"""
app/checks/cag/distributed_cache.py - Distributed Cache Consistency

Detect multi-node cache topology and test replication consistency.

Attack vectors:
- Inconsistent replication: poisoning affects only some users
- Node identification via response headers
- Load balancer patterns reveal infrastructure topology

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import time
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

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

    timeout_seconds = 120.0
    delay_between_targets = 0.3

    reason = "Inconsistent cache replication means poisoning is harder to detect and only affects some users"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["topology detection", "replication analysis", "node fingerprinting"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

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
                    topo_info = await self._detect_topology(client, url, service)

                    if topo_info:
                        dist_results.append(topo_info)

                        severity = self._determine_severity(topo_info)
                        result.findings.append(
                            build_finding(
                                check_name=self.name,
                                title=self._build_title(topo_info),
                                description=self._build_description(topo_info),
                                severity=severity,
                                evidence=self._build_evidence(topo_info),
                                host=service.host,
                                discriminator=f"dist-cache-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                                target=service,
                                target_url=url,
                                raw_data=topo_info,
                                references=self.references,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if dist_results:
            result.outputs["distributed_cache_info"] = dist_results

        return result

    async def _detect_topology(
        self, client: AsyncHttpClient, url: str, service: Service
    ) -> dict | None:
        """Detect cache topology by sending multiple requests."""
        test_query = f"distributed_cache_test_{int(time.time())}"
        payload = {"input": test_query, "query": test_query}

        node_observations = []
        response_bodies = []

        for i in range(TOPOLOGY_PROBE_COUNT):
            try:
                start = time.time()
                resp = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                elapsed = (time.time() - start) * 1000

                if resp.error:
                    continue

                # Collect node identity from headers
                node_id = self._extract_node_id(resp.headers)
                response_bodies.append(resp.body or "")

                node_observations.append(
                    {
                        "request_index": i,
                        "node_id": node_id,
                        "elapsed_ms": round(elapsed, 2),
                        "status_code": resp.status_code,
                    }
                )

            except Exception:
                continue

        if len(node_observations) < 3:
            return None

        # Analyze topology
        unique_nodes = {obs["node_id"] for obs in node_observations if obs["node_id"]}

        # Check response consistency
        unique_responses = set(response_bodies)
        content_consistent = len(unique_responses) <= 1

        # Detect load balancing pattern
        lb_pattern = self._detect_lb_pattern(node_observations)

        if not unique_nodes and content_consistent:
            return None

        return {
            "url": url,
            "total_requests": len(node_observations),
            "unique_nodes": list(unique_nodes),
            "node_count": len(unique_nodes),
            "content_consistent": content_consistent,
            "unique_responses": len(unique_responses),
            "lb_pattern": lb_pattern,
            "node_observations": node_observations,
        }

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
        """Determine finding severity."""
        if not topo_info.get("content_consistent") and topo_info.get("node_count", 0) > 1:
            return "medium"
        if topo_info.get("node_count", 0) > 1:
            return "low"
        return "info"

    def _build_title(self, topo_info: dict) -> str:
        """Build finding title."""
        n = topo_info.get("node_count", 0)

        if not topo_info.get("content_consistent") and n > 1:
            return f"Cache replication inconsistency: different content served by {n} nodes"
        if n > 1:
            return f"Multiple cache nodes detected: {n} nodes identified from response headers"
        return "Single cache node or consistent replication"

    def _build_description(self, topo_info: dict) -> str:
        """Build finding description."""
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
