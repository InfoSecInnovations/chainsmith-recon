"""
app/checks/cag/side_channel.py - Cache Side-Channel: Content Inference

Use timing differences to infer what other users have queried without
seeing their queries or responses.

Attack vectors:
- Cache hit (fast) on sensitive topic = someone recently queried it
- Timing oracle reveals user behavior patterns
- Privacy leak via side channel even without content access

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import statistics
import time
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

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

    timeout_seconds = 120.0
    delay_between_targets = 0.3

    reason = "Cache timing oracles leak user behavior patterns — knowing which topics are cached reveals what users are querying"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["timing analysis", "side-channel detection", "behavioral inference"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

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
                    sc_info = await self._probe_side_channel(client, url, service)

                    if sc_info:
                        side_channel_results.append(sc_info)

                        severity = self._determine_severity(sc_info)
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=self._build_title(sc_info),
                                description=self._build_description(sc_info),
                                severity=severity,
                                evidence=self._build_evidence(sc_info),
                                host=service.host,
                                discriminator=f"side-channel-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                                target=service,
                                target_url=url,
                                raw_data=sc_info,
                                references=self.references,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if side_channel_results:
            result.outputs["side_channel_risk"] = side_channel_results

        return result

    async def _probe_side_channel(
        self, client: AsyncHttpClient, url: str, service: Service
    ) -> dict | None:
        """Probe for cache timing side-channel."""
        # Get baseline: unique query that should always be a cache miss
        baseline_timings = []
        for i in range(3):
            unique_query = f"baseline_unique_query_{int(time.time())}_{i}_xyzzy"
            start = time.time()
            resp = await client.post(
                url,
                json={"input": unique_query, "query": unique_query},
                headers={"Content-Type": "application/json"},
            )
            elapsed = (time.time() - start) * 1000

            if resp.error or resp.status_code >= 400:
                if i == 0:
                    return None
                continue

            baseline_timings.append(elapsed)

        if not baseline_timings:
            return None

        baseline_mean = statistics.mean(baseline_timings)
        baseline_stddev = statistics.stdev(baseline_timings) if len(baseline_timings) > 1 else 0

        # Cache hit threshold: significantly faster than baseline
        cache_hit_threshold = baseline_mean * 0.5

        # Probe each sensitive topic
        topic_results = []
        cache_hits = 0

        for topic in PROBE_TOPICS:
            timings = []
            for _ in range(3):
                start = time.time()
                resp = await client.post(
                    url,
                    json={"input": topic, "query": topic},
                    headers={"Content-Type": "application/json"},
                )
                elapsed = (time.time() - start) * 1000

                if not resp.error:
                    timings.append(elapsed)

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

        # Determine if there's meaningful timing variance
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
