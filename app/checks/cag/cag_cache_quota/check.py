"""
app/checks/cag/cache_quota.py - Cache Quota/Size Exploitation

Test cache size limits and eviction behavior under load.

Attack vectors:
- Cache exhaustion: flood with garbage to evict legitimate entries
- Unbounded cache: memory exhaustion risk
- LRU eviction abuse: targeted eviction of specific entries

**Probe/grade.** The probe sends the whole flood sequence —
a baseline query twice, `MAX_TEST_ENTRIES` unique fills, then a re-query of the
first five and last three — and records every request. `_test_quota()` is the
one parser both halves call (§0.12); it rebuilds the capacity reading off the
recorded bytes, and two of its moves are the conventions this check contributes:

- **Timing is read back, not re-measured.** The original wrapped every `await`
  in `time.monotonic()`; those numbers cannot be reproduced from a corpus, so
  the reading takes `Exchange.elapsed_ms` and a re-grade reaches the same
  eviction verdict about the same requests.
- **A re-queried entry is its query's *second* recorded occurrence.** The fill
  and the re-query carry byte-identical bodies, so which is which is recovered
  from recorded order (the `agent_context_overflow` rule, §0.15); the entry
  index is read from the `quota_test_<id>_<i>` marker in the body.

**Fixed**: one candidate per endpoint, the discriminator
embeds the path, so the contract carries no map and `grade()` places the
severity (the `ai_model_info_check` pattern). Confidence is where the split
pays, because eviction here is inferred entirely from response *timing*: an LLM
pipeline returns identical text for a repeated query at temperature 0 with no
cache at all, and a slow re-query can be load rather than an evicted entry.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import re
import uuid
from collections import defaultdict
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Max entries to test (keep low to avoid impacting production)
MAX_TEST_ENTRIES = 50

_INDEX_RE = re.compile(r"quota_test_[0-9a-f]+_(\d+)")


class CacheQuotaCheck(ServiceIteratingCheck):
    """
    Test cache size limits and eviction behavior under load.

    Sends unique queries to fill the cache and then re-queries early
    entries to detect eviction. Estimates approximate cache capacity.
    """

    name = "cag_cache_quota"
    description = "Test cache size limits and eviction behavior under load"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["cache_size"]
    service_types = ["ai", "api", "http"]

    reason = "Cache exhaustion enables targeted eviction of legitimate entries and potential memory exhaustion on unbounded caches"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache flooding", "eviction analysis", "capacity estimation"]

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
        quota_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"quota-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                        target=service,
                        target_url=url,
                    )
                    await self._flood(client, url, scan_id, service.host, candidate)

                    quota_info = self._test_quota(candidate.exchanges)
                    if quota_info:
                        quota_results.append(quota_info)
                        result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if quota_results:
            result.outputs["cache_size"] = quota_results

        return result

    async def _flood(
        self, client: AsyncHttpClient, url: str, scan_id: str, host: str, candidate
    ) -> None:
        """Send the baseline + fill + re-query sequence and record every request."""
        test_id = uuid.uuid4().hex[:8]

        # Baseline, sent twice.
        baseline_query = f"quota_baseline_{test_id}_{uuid.uuid4().hex[:6]}"
        r1 = await self._post(client, url, baseline_query, scan_id, host)
        candidate.attach(r1)
        if self._failed(r1):
            return
        r2 = await self._post(client, url, baseline_query, scan_id, host)
        candidate.attach(r2)
        if r2 is None or r2.error:
            return

        # Fill the cache with unique entries.
        queries = []
        for i in range(MAX_TEST_ENTRIES):
            query = f"quota_test_{test_id}_{i}"
            queries.append(query)
            candidate.attach(await self._post(client, url, query, scan_id, host))

        # Re-query the first few, then the last few. Same body as the fill, so
        # the reading tells them apart by recorded order.
        check_count = min(5, len(queries))
        for i in range(check_count):
            candidate.attach(await self._post(client, url, queries[i], scan_id, host))
        for i in range(max(0, len(queries) - 3), len(queries)):
            candidate.attach(await self._post(client, url, queries[i], scan_id, host))

    async def _post(
        self, client: AsyncHttpClient, url: str, query: str, scan_id: str, host: str
    ) -> Exchange | None:
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

    @staticmethod
    def _failed(exchange: Exchange | None) -> bool:
        return exchange is None or bool(exchange.error) or (exchange.response_status or 0) >= 400

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        quota_info = self._test_quota(list(evidence))
        if not quota_info:
            return []

        severity = self._determine_severity(quota_info)
        confidence, why = self._confidence(quota_info)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=None,
                title=self._build_title(quota_info),
                description=self._build_description(quota_info),
                evidence=self._build_evidence(quota_info),
                reasoning=why,
                signals={
                    "eviction_detected": quota_info["eviction_detected"],
                    "unbounded": quota_info["unbounded"],
                    "early_entries_evicted": quota_info["early_entries_evicted"],
                    "estimated_capacity": quota_info["estimated_capacity"],
                },
                references=self.references,
                raw_data=quota_info,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    @staticmethod
    def _confidence(quota_info: dict) -> tuple[float, str]:
        if quota_info.get("eviction_detected"):
            return 0.45, (
                f"{quota_info['early_entries_evicted']} of "
                f"{quota_info['early_entries_checked']} early entries answered slower than the "
                "cache-hit threshold after the flood — but eviction is inferred from response "
                "timing alone, not from reading the cache, and a slow re-query is as easily "
                "load or jitter as an evicted entry"
            )
        if quota_info.get("unbounded"):
            return 0.4, (
                f"all {quota_info['total_entries_sent']} entries still answered fast and none "
                "were evicted, but 'unbounded' rests on the same timing proxy: a cache large "
                "enough to hold the test set looks identical to one with no limit at all over "
                "this few requests"
            )
        return 0.35, (
            "capacity is an estimate from where re-query timings crossed a threshold derived "
            "from a single baseline pair; the split between hit and miss is a guess when an LLM "
            "at temperature 0 returns identical text for a repeated query with no cache"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _test_quota(self, exchanges: list[Exchange]) -> dict | None:
        """Rebuild the capacity reading off the recorded flood.

        Baseline pair first (paired by recorded order), then the fill/re-query
        entries keyed on the `quota_test_<id>_<i>` marker; the re-query is each
        query's second recorded occurrence. All timing is `elapsed_ms`.
        """
        posts = [
            e
            for e in exchanges
            if e.request_method == "POST" and not e.error and (e.response_status or 0) < 400
        ]

        baselines = [e for e in posts if "quota_baseline" in (e.request_body or "")]
        if len(baselines) < 2:
            return None
        baseline_ms = baselines[0].elapsed_ms
        cached_ms = baselines[1].elapsed_ms
        if not baseline_ms or cached_ms is None:
            return None
        # If no caching detected, the original skipped this endpoint.
        if cached_ms >= baseline_ms * 0.7:
            return None
        threshold = baseline_ms * 0.7

        occurrences: dict[int, list[Exchange]] = defaultdict(list)
        for e in posts:
            match = _INDEX_RE.search(e.request_body or "")
            if match:
                occurrences[int(match.group(1))].append(e)

        indices = sorted(occurrences)
        n = len(indices)
        check_count = min(5, n)

        evicted_count = 0
        for i in indices[:check_count]:
            requery = occurrences[i][1] if len(occurrences[i]) >= 2 else None
            if requery is not None and (requery.elapsed_ms or 0) >= threshold:
                evicted_count += 1

        last_cached = 0
        for i in indices[max(0, n - 3) :]:
            requery = occurrences[i][1] if len(occurrences[i]) >= 2 else None
            if (
                requery is not None
                and requery.elapsed_ms is not None
                and requery.elapsed_ms < threshold
            ):
                last_cached += 1

        return {
            "url": baselines[0].request_url,
            "total_entries_sent": MAX_TEST_ENTRIES,
            "early_entries_evicted": evicted_count,
            "early_entries_checked": check_count,
            "last_entries_cached": last_cached,
            "baseline_ms": round(baseline_ms, 2),
            "cached_ms": round(cached_ms, 2),
            "eviction_detected": evicted_count > 0,
            "unbounded": evicted_count == 0 and last_cached > 0,
            "estimated_capacity": (
                MAX_TEST_ENTRIES if evicted_count == 0 else MAX_TEST_ENTRIES - evicted_count
            ),
        }

    def _determine_severity(self, quota_info: dict) -> str:
        """Determine observation severity."""
        if quota_info.get("eviction_detected"):
            return "medium"
        if quota_info.get("unbounded"):
            return "medium"
        return "low"

    def _build_title(self, quota_info: dict) -> str:
        """Build observation title."""
        if quota_info.get("eviction_detected"):
            n = quota_info["early_entries_evicted"]
            return f"Cache exhaustion possible: {n} early entries evicted (LRU eviction confirmed)"
        if quota_info.get("unbounded"):
            n = quota_info["total_entries_sent"]
            return (
                f"Unbounded cache: {n} queries accepted with no eviction (memory exhaustion risk)"
            )
        return f"Cache size limited: approximately {quota_info['estimated_capacity']} entries"

    def _build_description(self, quota_info: dict) -> str:
        """Build observation description."""
        if quota_info.get("eviction_detected"):
            return (
                f"After sending {quota_info['total_entries_sent']} unique queries, "
                f"{quota_info['early_entries_evicted']}/{quota_info['early_entries_checked']} "
                f"early entries were evicted from cache. An attacker can flush valuable "
                f"cache entries by flooding with garbage queries, degrading performance "
                f"for legitimate users."
            )
        if quota_info.get("unbounded"):
            return (
                f"Cache accepted {quota_info['total_entries_sent']} unique entries "
                f"with no eviction detected. Unbounded caches risk memory exhaustion "
                f"under sustained load."
            )
        return (
            f"Cache appears limited to approximately {quota_info['estimated_capacity']} entries. "
            f"Capacity testing inconclusive."
        )

    def _build_evidence(self, quota_info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Entries sent: {quota_info['total_entries_sent']}",
            f"Early entries evicted: {quota_info['early_entries_evicted']}/{quota_info['early_entries_checked']}",
            f"Last entries cached: {quota_info['last_entries_cached']}",
            f"Baseline timing: {quota_info['baseline_ms']}ms (uncached)",
            f"Cached timing: {quota_info['cached_ms']}ms",
        ]
        return "\n".join(lines)
