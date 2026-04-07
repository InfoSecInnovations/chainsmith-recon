"""
app/checks/cag/semantic_threshold.py - Semantic Cache Similarity Threshold Probing

Probe the similarity threshold of semantic caches to estimate the blast
radius of cache poisoning attacks.

Attack vectors:
- Loose threshold: poisoned entry serves many query variations
- Tight threshold: limited blast radius but still exploitable
- Threshold mapping enables targeted poisoning of broad query sets

References:
  https://github.com/zilliztech/GPTCache
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import asyncio
import time
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

# Query variations with decreasing similarity to baseline
SIMILARITY_PROBES = [
    {"query": "What is the capital of France?", "similarity": 1.0, "label": "exact"},
    {"query": "What's the capital of France?", "similarity": 0.95, "label": "minor_variation"},
    {"query": "Tell me France's capital city", "similarity": 0.85, "label": "rephrased"},
    {"query": "What is the main city of France?", "similarity": 0.70, "label": "related"},
    {"query": "Tell me about France", "similarity": 0.50, "label": "tangential"},
    {"query": "What is the weather today?", "similarity": 0.10, "label": "unrelated"},
]


class SemanticThresholdCheck(ServiceIteratingCheck):
    """
    Probe semantic cache similarity threshold to estimate poisoning blast radius.

    Sends a baseline query to populate the cache, then sends variations
    with decreasing semantic similarity. Uses timing to detect which
    variations hit the cache, estimating the similarity threshold.
    """

    name = "cag_semantic_threshold"
    description = "Probe semantic cache similarity threshold to estimate poisoning blast radius"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["similarity_threshold"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 120.0
    delay_between_targets = 0.3

    reason = "A loose semantic cache threshold widens the blast radius of cache poisoning — one poisoned entry could serve dozens of query variations"
    references = [
        "https://github.com/zilliztech/GPTCache",
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["semantic threshold probing", "timing analysis", "similarity estimation"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cag_endpoints = context.get("cag_endpoints", [])
        service_endpoints = [
            ep for ep in cag_endpoints if ep.get("service", {}).get("host") == service.host
        ]

        if not service_endpoints:
            return result

        # Check if semantic cache is known
        cache_infra = context.get("cache_infrastructure", [])
        has_semantic = (
            any(t in cache_infra for t in ["semantic_cache", "gptcache"]) if cache_infra else False
        )

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        threshold_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    threshold_info = await self._probe_threshold(client, url, service, has_semantic)

                    if threshold_info:
                        threshold_results.append(threshold_info)

                        severity = self._determine_severity(threshold_info)
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=self._build_title(threshold_info),
                                description=self._build_description(threshold_info),
                                severity=severity,
                                evidence=self._build_evidence(threshold_info),
                                host=service.host,
                                discriminator=f"threshold-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                                target=service,
                                target_url=url,
                                raw_data=threshold_info,
                                references=self.references,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if threshold_results:
            result.outputs["similarity_threshold"] = threshold_results

        return result

    async def _probe_threshold(
        self, client: AsyncHttpClient, url: str, service: Service, has_semantic: bool
    ) -> dict | None:
        """Probe the semantic similarity threshold."""
        baseline_query = SIMILARITY_PROBES[0]["query"]

        # Establish baseline: cold request
        start_cold = time.time()
        resp_cold = await client.post(
            url,
            json={"input": baseline_query, "query": baseline_query},
            headers={"Content-Type": "application/json"},
        )
        cold_ms = (time.time() - start_cold) * 1000

        if resp_cold.error or resp_cold.status_code >= 400:
            return None

        baseline_body = resp_cold.body or ""

        # Confirm caching: re-send exact query
        start_hot = time.time()
        resp_hot = await client.post(
            url,
            json={"input": baseline_query, "query": baseline_query},
            headers={"Content-Type": "application/json"},
        )
        hot_ms = (time.time() - start_hot) * 1000

        if resp_hot.error:
            return None

        # Check if caching is working
        if hot_ms >= cold_ms * 0.7:
            return None

        cache_hit_threshold_ms = cold_ms * 0.7

        # Test each variation
        probe_results = []
        for probe in SIMILARITY_PROBES[1:]:  # Skip exact duplicate
            await asyncio.sleep(0.3)

            start = time.time()
            resp = await client.post(
                url,
                json={"input": probe["query"], "query": probe["query"]},
                headers={"Content-Type": "application/json"},
            )
            elapsed = (time.time() - start) * 1000

            if resp.error:
                continue

            is_cache_hit = elapsed < cache_hit_threshold_ms
            content_matches = (resp.body or "") == baseline_body

            probe_results.append(
                {
                    "label": probe["label"],
                    "query": probe["query"],
                    "similarity": probe["similarity"],
                    "elapsed_ms": round(elapsed, 2),
                    "cache_hit": is_cache_hit,
                    "content_matches": content_matches,
                }
            )

        if not probe_results:
            return None

        # Determine estimated threshold
        hits = [p for p in probe_results if p["cache_hit"]]
        misses = [p for p in probe_results if not p["cache_hit"]]

        if hits:
            # Threshold is between lowest hit similarity and highest miss similarity
            lowest_hit = min(h["similarity"] for h in hits)
            highest_miss = max(m["similarity"] for m in misses) if misses else 0
            estimated_threshold = (lowest_hit + highest_miss) / 2
        else:
            estimated_threshold = 1.0  # Exact match only

        is_semantic = len(hits) > 0 and any(
            h["label"] in ("rephrased", "related", "tangential") for h in hits
        )

        return {
            "url": url,
            "cold_ms": round(cold_ms, 2),
            "hot_ms": round(hot_ms, 2),
            "is_semantic_cache": is_semantic,
            "estimated_threshold": round(estimated_threshold, 2),
            "variations_hit": len(hits),
            "variations_tested": len(probe_results),
            "probe_results": probe_results,
            "semantic_cache_known": has_semantic,
        }

    def _determine_severity(self, threshold_info: dict) -> str:
        """Determine observation severity."""
        if not threshold_info.get("is_semantic_cache"):
            return "info"

        threshold = threshold_info.get("estimated_threshold", 1.0)
        hits = threshold_info.get("variations_hit", 0)

        if threshold <= 0.6 or hits >= 4:
            return "high"
        if threshold <= 0.8 or hits >= 2:
            return "medium"
        return "low"

    def _build_title(self, threshold_info: dict) -> str:
        """Build observation title."""
        if not threshold_info.get("is_semantic_cache"):
            return "Not a semantic cache (exact match only)"

        threshold = threshold_info["estimated_threshold"]
        hits = threshold_info["variations_hit"]

        if threshold <= 0.6:
            return f"Loose semantic cache threshold: poisoned entry could serve {hits} query variations (threshold ~{threshold})"
        if threshold <= 0.8:
            return f"Semantic cache hit on rephrased queries (threshold ~{threshold})"
        return "Semantic cache only matches near-exact queries (tight threshold)"

    def _build_description(self, threshold_info: dict) -> str:
        """Build observation description."""
        if not threshold_info.get("is_semantic_cache"):
            return (
                "Cache only matches exact queries. Not a semantic cache, or "
                "similarity threshold is very tight."
            )

        threshold = threshold_info["estimated_threshold"]
        hits = threshold_info["variations_hit"]
        total = threshold_info["variations_tested"]

        return (
            f"Semantic cache detected with an estimated similarity threshold of ~{threshold}. "
            f"{hits}/{total} query variations produced cache hits. "
            f"A lower threshold means a single poisoned cache entry could serve a wider "
            f"range of queries, amplifying the blast radius of cache poisoning attacks."
        )

    def _build_evidence(self, threshold_info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Estimated threshold: {threshold_info['estimated_threshold']}",
            f"Cold request: {threshold_info['cold_ms']}ms",
            f"Hot request: {threshold_info['hot_ms']}ms",
            f"Variations hit: {threshold_info['variations_hit']}/{threshold_info['variations_tested']}",
            "",
        ]

        for p in threshold_info.get("probe_results", []):
            hit_str = "HIT" if p["cache_hit"] else "MISS"
            lines.append(f"  [{hit_str}] {p['label']} (sim={p['similarity']}): {p['elapsed_ms']}ms")

        return "\n".join(lines)
