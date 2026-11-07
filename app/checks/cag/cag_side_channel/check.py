"""
app/checks/cag/side_channel.py - Cache Side-Channel: Content Inference

Use timing differences to infer what other users have queried without
seeing their queries or responses.

Attack vectors:
- Cache hit (fast) on sensitive topic = someone recently queried it
- Timing oracle reveals user behavior patterns
- Privacy leak via side channel even without content access

**Probe/grade.** The probe fires the baseline and every
topic query, records all of them, and hands them over as one candidate per
endpoint (the observation's `target_url` is the endpoint, so it cannot be one
candidate per service — §0.15). `grade()` re-reads the recorded exchanges and
rebuilds the timing analysis; `_reading()` is the one parser both halves call
(§0.12), and two things it does are the conventions this check contributes:

- **Timing is read back, not re-measured.** The original wrapped each request in
  `time.time()`. That number cannot be reproduced from a corpus, so the reading
  takes `Exchange.elapsed_ms` — the transport-measured latency the client
  already records — and a re-grade reaches the same fast/slow verdict about the
  same requests.
- **Which query an exchange asked is recovered from its own recorded body**
  (`_topic_of`), so baseline probes and each sensitive topic are told apart
  without trusting the order they were sent in.

**Fixed**: the discriminator embeds the endpoint path, an
open set, so the contract declares no `observations:` map and `grade()` places
the severity. Confidence is where the split pays: a cache-hit inference rests on
response time alone, and network jitter or model load produces the same fast
response with no cache at all.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import json
import statistics
import time
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Sensitive topics to probe (report capability, not specifics)
PROBE_TOPICS = [
    "salary information and compensation data",
    "merger and acquisition plans",
    "employee performance reviews",
    "api keys and credentials",
    "security vulnerabilities in production",
    "financial projections and revenue",
    "customer personal data and records",
    "password reset procedures",
]

BASELINE_PREFIX = "baseline_unique_query_"


class SideChannelCheck(ServiceIteratingCheck):
    """
    Detect cache timing side-channels that reveal user query patterns.

    Sends queries about sensitive topics and measures response time.
    A cache hit (fast response) indicates the topic was recently queried
    by another user, creating a privacy-leaking timing oracle.
    """

    name = "cag_side_channel"
    description = "Detect cache timing side-channels that reveal user query patterns"
    intrusive = False

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["side_channel_risk"]
    service_types = ["ai", "api", "http"]

    reason = "Cache timing oracles leak user behavior patterns — knowing which topics are cached reveals what users are querying"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["timing analysis", "side-channel detection", "behavioral inference"]

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

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        side_channel_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    path = endpoint.get("path", "unknown")
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"side-channel-{path.strip('/').replace('/', '-')}",
                        target=service,
                        target_url=url,
                    )

                    # Baseline: unique queries that should always be cache misses.
                    for i in range(3):
                        unique_query = f"{BASELINE_PREFIX}{int(time.time())}_{i}_xyzzy"
                        candidate.attach(
                            await self._send(client, url, unique_query, scan_id, service.host)
                        )

                    # Each sensitive topic, three times.
                    for topic in PROBE_TOPICS:
                        for _ in range(3):
                            candidate.attach(
                                await self._send(client, url, topic, scan_id, service.host)
                            )

                    result.candidates.append(candidate)
                    reading = self._reading(candidate.exchanges, url)
                    if reading:
                        side_channel_results.append(reading)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if side_channel_results:
            result.outputs["side_channel_risk"] = side_channel_results

        return result

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
        sc_info = self._reading(list(evidence), ctx.target_url or "")
        if sc_info is None:
            # Baseline never answered, or no topic produced a usable response —
            # the original returned None here and emitted no observation.
            return []

        severity = self._determine_severity(sc_info)
        confidence, why = self._confidence(sc_info)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=None,  # inherit the candidate's path discriminator
                title=self._build_title(sc_info),
                description=self._build_description(sc_info),
                evidence=self._build_evidence(sc_info),
                reasoning=why,
                signals={
                    "cache_hits": sc_info["cache_hits"],
                    "topics_tested": sc_info["topics_tested"],
                    "timing_variance_ratio": sc_info["timing_variance_ratio"],
                    "timing_oracle_available": sc_info["timing_oracle_available"],
                },
                references=self.references,
                raw_data=sc_info,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    @staticmethod
    def _confidence(sc_info: dict) -> tuple[float, str]:
        if sc_info.get("cache_hits", 0) > 0:
            return 0.4, (
                "the cache-hit call rests on response time alone — a topic query that ran "
                "faster than half the baseline mean. Network jitter, a warm model or an "
                "unrelated load dip produces the same fast response with no cache involved, "
                "and no cache header corroborates the timing"
            )
        if sc_info.get("timing_oracle_available"):
            return 0.3, (
                "'oracle available' means only that response times varied by more than 30% of "
                "the baseline across topics; variance that size is routine for an LLM backend "
                "answering different-length prompts, so this is a weak signal for a cache"
            )
        return 0.5, (
            "the inconclusive reading is the honest one — the timings showed no clear "
            "hit/miss split — but it is bounded by a small sample (three requests per topic) "
            "and a coarse threshold"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange], url: str) -> dict | None:
        """Rebuild the side-channel reading off the recorded exchanges' latencies.

        Baseline requests and each sensitive topic are told apart by their own
        recorded request body, and every latency is `Exchange.elapsed_ms` rather
        than a re-measured wall-clock delta.
        """
        baseline_timings = [
            e.elapsed_ms
            for e in exchanges
            if self._is_baseline(e) and self._usable(e) and e.elapsed_ms is not None
        ]
        if not baseline_timings:
            return None

        baseline_mean = statistics.mean(baseline_timings)
        baseline_stddev = statistics.stdev(baseline_timings) if len(baseline_timings) > 1 else 0
        cache_hit_threshold = baseline_mean * 0.5

        topic_results = []
        cache_hits = 0
        for topic in PROBE_TOPICS:
            timings = [
                e.elapsed_ms
                for e in exchanges
                if self._topic_of(e) == topic and not e.error and e.elapsed_ms is not None
            ]
            if not timings:
                continue

            topic_mean = statistics.mean(timings)
            topic_stddev = statistics.stdev(timings) if len(timings) > 1 else 0
            is_cache_hit = topic_mean < cache_hit_threshold and topic_stddev < baseline_mean * 0.3
            if is_cache_hit:
                cache_hits += 1

            topic_results.append(
                {
                    "topic_index": PROBE_TOPICS.index(topic),
                    "mean_ms": round(topic_mean, 2),
                    "stddev_ms": round(topic_stddev, 2),
                    "cache_hit": is_cache_hit,
                }
            )

        if not topic_results:
            return None

        all_means = [t["mean_ms"] for t in topic_results]
        timing_variance = (
            (max(all_means) - min(all_means)) / baseline_mean if baseline_mean > 0 else 0
        )

        return {
            "url": url,
            "baseline_mean_ms": round(baseline_mean, 2),
            "baseline_stddev_ms": round(baseline_stddev, 2),
            "cache_hit_threshold_ms": round(cache_hit_threshold, 2),
            "topics_tested": len(topic_results),
            "cache_hits": cache_hits,
            "timing_variance_ratio": round(timing_variance, 2),
            "timing_oracle_available": timing_variance > 0.3,
            "topic_results": topic_results,
        }

    @staticmethod
    def _input_of(exchange: Exchange) -> str:
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return ""
        return body.get("input", "") if isinstance(body, dict) else ""

    def _is_baseline(self, exchange: Exchange) -> bool:
        return BASELINE_PREFIX in self._input_of(exchange)

    def _topic_of(self, exchange: Exchange) -> str | None:
        value = self._input_of(exchange)
        return value if value in PROBE_TOPICS else None

    @staticmethod
    def _usable(exchange: Exchange) -> bool:
        return not exchange.error and (exchange.response_status or 0) < 400

    def _determine_severity(self, sc_info: dict) -> str:
        """Determine observation severity."""
        hits = sc_info.get("cache_hits", 0)
        total = sc_info.get("topics_tested", 0)

        if hits > 0 and total > 0:
            return "medium"
        if sc_info.get("timing_oracle_available"):
            return "low"
        return "info"

    def _build_title(self, sc_info: dict) -> str:
        """Build observation title."""
        hits = sc_info.get("cache_hits", 0)
        total = sc_info.get("topics_tested", 0)

        if hits > 0:
            return f"Cache timing side-channel: {hits}/{total} sensitive topic queries showed cache hits"
        if sc_info.get("timing_oracle_available"):
            return "Cache timing oracle available: significant response time variance detected"
        return "Timing analysis inconclusive (no clear cache hit/miss pattern)"

    def _build_description(self, sc_info: dict) -> str:
        """Build observation description."""
        hits = sc_info.get("cache_hits", 0)

        if hits > 0:
            return (
                f"Cache timing analysis revealed {hits} sensitive topic queries with "
                f"response times consistent with cache hits. This indicates other users "
                f"recently queried these topics. Even without accessing cached content, "
                f"the timing oracle reveals user behavior patterns, creating a privacy leak."
            )
        if sc_info.get("timing_oracle_available"):
            return (
                "Significant response time variance detected between queries, indicating "
                "a timing oracle is available. An attacker can infer which topics are "
                "actively being queried by other users."
            )
        return (
            "No clear cache hit/miss timing pattern detected. The timing oracle is "
            "not reliable enough for behavioral inference."
        )

    def _build_evidence(self, sc_info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Baseline: {sc_info['baseline_mean_ms']}ms (stddev: {sc_info['baseline_stddev_ms']}ms)",
            f"Cache hit threshold: {sc_info['cache_hit_threshold_ms']}ms",
            f"Cache hits: {sc_info['cache_hits']}/{sc_info['topics_tested']}",
            f"Timing variance ratio: {sc_info['timing_variance_ratio']}",
            "",
        ]

        for t in sc_info.get("topic_results", []):
            hit_str = "HIT" if t["cache_hit"] else "MISS"
            lines.append(
                f"  Topic {t['topic_index']}: [{hit_str}] "
                f"{t['mean_ms']}ms (stddev: {t['stddev_ms']}ms)"
            )

        return "\n".join(lines)
