"""
app/checks/cag/semantic_threshold.py - Semantic Cache Similarity Threshold Probing

Probe the similarity threshold of semantic caches to estimate the blast
radius of cache poisoning attacks.

Attack vectors:
- Loose threshold: poisoned entry serves many query variations
- Tight threshold: limited blast radius but still exploitable
- Threshold mapping enables targeted poisoning of broad query sets

**Probe/grade.** The probe sends the baseline query twice
(cold, then hot) and each similarity variation once, records every exchange, and
hands them over as one candidate per endpoint. `_reading()` is the one parser
both halves call (§0.12), and two things it does are the conventions this check
contributes:

- **Timing is read back, not re-measured.** The original wrapped every request
  in `time.time()`; those numbers cannot be reproduced from a corpus, so the
  reading takes `Exchange.elapsed_ms` instead and a re-grade reaches the same
  cache-hit/miss decision about the same requests.
- **The byte-identical cold/hot pair is told apart by recorded order** (§0.15):
  both carry the baseline query, so the first is the cold request and the second
  the hot one. Variations carry distinct queries and are matched by body.

`grade()` never sees the discriminator (§0.16); it identifies the endpoint from
`ctx.target_url`.

**Fixed**: the discriminator embeds the endpoint path, an
unbounded value, so the contract declares no `observations:` map and `grade()`
places the real severity. Confidence is where the split pays: the whole reading
rests on latency deltas, and a single fast response is as easily network jitter
or a warm connection as a genuine semantic cache hit — the six similarity buckets
are coarse, so the estimated threshold is an order-of-magnitude figure at best.

References:
  https://github.com/zilliztech/GPTCache
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import asyncio
import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

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

    reason = "A loose semantic cache threshold widens the blast radius of cache poisoning — one poisoned entry could serve dozens of query variations"
    references = [
        "https://github.com/zilliztech/GPTCache",
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["semantic threshold probing", "timing analysis", "similarity estimation"]

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
                    path = endpoint.get("path", "unknown").strip("/").replace("/", "-")
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"threshold-{path}",
                        target=service,
                        target_url=url,
                    )

                    stop = await self._probe(client, url, service, scan_id, candidate)
                    if stop:
                        continue

                    reading = self._reading(candidate.exchanges, url, has_semantic)
                    if reading:
                        threshold_results.append(reading)
                        result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if threshold_results:
            result.outputs["similarity_threshold"] = threshold_results

        return result

    async def _probe(
        self,
        client: AsyncHttpClient,
        url: str,
        service: Service,
        scan_id: str,
        candidate,
    ) -> bool:
        """Send the probe requests, recording each. Returns True to skip this
        endpoint (the original returned None before emitting a result): a failed
        baseline, or caching not confirmed on the hot request. Both decisions are
        made on the exchange just recorded (§6.2)."""
        baseline_query = SIMILARITY_PROBES[0]["query"]

        cold = await self._send(client, url, baseline_query, scan_id, service.host)
        candidate.attach(cold)
        if cold.error or (cold.response_status or 0) >= 400:
            return True

        hot = await self._send(client, url, baseline_query, scan_id, service.host)
        candidate.attach(hot)
        if hot.error:
            return True
        # Caching must be confirmed on the exact repeat before variations mean
        # anything (read off the record, not a re-measured await).
        if hot.elapsed_ms is None or cold.elapsed_ms is None:
            return True
        if hot.elapsed_ms >= cold.elapsed_ms * 0.7:
            return True

        for probe in SIMILARITY_PROBES[1:]:
            await asyncio.sleep(0.3)
            candidate.attach(await self._send(client, url, probe["query"], scan_id, service.host))

        return False

    async def _send(
        self, client: AsyncHttpClient, url: str, query: str, scan_id: str, host: str
    ) -> Exchange:
        body = {"input": query, "query": query}
        resp = await client.post(url, json=body, headers=JSON_HEADERS)
        return exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="POST",
            request_headers=JSON_HEADERS,
            request_json=body,
        )

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        has_semantic = bool((ctx.context or {}).get("cache_infrastructure")) and any(
            t in (ctx.context or {}).get("cache_infrastructure", [])
            for t in ["semantic_cache", "gptcache"]
        )
        reading = self._reading(list(evidence), ctx.target_url or "", has_semantic)
        if not reading:
            return []

        severity = self._determine_severity(reading)
        confidence, why = self._confidence(reading)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                title=self._build_title(reading),
                description=self._build_description(reading),
                evidence=self._build_evidence(reading),
                reasoning=why,
                signals={
                    "is_semantic_cache": reading["is_semantic_cache"],
                    "estimated_threshold": reading["estimated_threshold"],
                    "variations_hit": reading["variations_hit"],
                },
                references=self.references,
                raw_data=reading,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    @staticmethod
    def _confidence(reading: dict) -> tuple[float, str]:
        if not reading.get("is_semantic_cache"):
            return 0.5, (
                "no variation returned faster than the cold-request baseline, but a semantic "
                "cache with a tight threshold looks identical to no cache at all on timing alone"
            )
        hits = reading.get("variations_hit", 0)
        if hits >= 4:
            return 0.55, (
                "several variations returned markedly faster than the cold baseline, a strong "
                "timing signal — still timing only: a warm connection or server-side jitter can "
                "produce the same latency drop without any semantic match"
            )
        return 0.4, (
            "the reading rests entirely on latency deltas across six coarse similarity buckets; "
            "one or two fast variations is as easily network jitter as a genuine cache hit, so "
            "the estimated threshold is indicative, not measured"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange], url: str, has_semantic: bool) -> dict | None:
        """Rebuild the threshold reading off the recorded exchanges.

        The baseline query is sent twice; the first recorded is the cold request
        and the second the hot one (§0.15). Variations carry distinct queries.
        """
        posts = [e for e in exchanges if e.request_url == url and e.request_method == "POST"]
        baseline_query = SIMILARITY_PROBES[0]["query"]
        baseline = [e for e in posts if self._query_of(e) == baseline_query]
        if len(baseline) < 2:
            return None

        cold, hot = baseline[0], baseline[1]
        if cold.error or (cold.response_status or 0) >= 400 or hot.error:
            return None
        if cold.elapsed_ms is None or hot.elapsed_ms is None:
            return None
        cold_ms, hot_ms = cold.elapsed_ms, hot.elapsed_ms
        if hot_ms >= cold_ms * 0.7:
            return None

        baseline_body = cold.response_body or ""
        cache_hit_threshold_ms = cold_ms * 0.7

        probe_results = []
        for probe in SIMILARITY_PROBES[1:]:
            exchange = next((e for e in posts if self._query_of(e) == probe["query"]), None)
            if exchange is None or exchange.error or exchange.elapsed_ms is None:
                continue
            elapsed = exchange.elapsed_ms
            probe_results.append(
                {
                    "label": probe["label"],
                    "query": probe["query"],
                    "similarity": probe["similarity"],
                    "elapsed_ms": round(elapsed, 2),
                    "cache_hit": elapsed < cache_hit_threshold_ms,
                    "content_matches": (exchange.response_body or "") == baseline_body,
                }
            )

        if not probe_results:
            return None

        hits = [p for p in probe_results if p["cache_hit"]]
        misses = [p for p in probe_results if not p["cache_hit"]]

        if hits:
            lowest_hit = min(h["similarity"] for h in hits)
            highest_miss = max(m["similarity"] for m in misses) if misses else 0
            estimated_threshold = (lowest_hit + highest_miss) / 2
        else:
            estimated_threshold = 1.0

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

    @staticmethod
    def _query_of(exchange: Exchange) -> str:
        try:
            body = json.loads(exchange.request_body or "{}")
        except (json.JSONDecodeError, TypeError):
            return ""
        if not isinstance(body, dict):
            return ""
        value = body.get("query")
        return value if isinstance(value, str) else ""

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
