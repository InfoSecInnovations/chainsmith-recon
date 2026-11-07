"""
app/checks/cag/ttl_mapping.py - TTL/Expiry Mapping

Determine cache TTL by re-querying at increasing intervals and detecting
the transition from cache hit to cache miss.

Attack vectors:
- Long TTL increases poisoning exposure window
- No TTL = indefinite caching = highest risk
- TTL mismatch between headers and actual behavior

**Probe/grade.** The probe drives the timing sequence —
one warm-up pair then a re-query at each interval — records every request as an
exchange, and hands over one candidate per endpoint (each observation names its
own `target_url`, so it is candidate-per-endpoint, §0.15, not one per service).
`grade()` re-reads the recorded exchanges and places the severity. Three things
this check contributes:

- **Timing is read back, not re-measured** (§0.12). The original wrapped each
  `await` in `time.time()`; those numbers cannot be reproduced from a corpus, so
  `_reading()` takes `Exchange.elapsed_ms` instead and a re-grade reaches the
  same hit/miss decision about the same requests.
- **Byte-identical requests are paired by recorded order** (§0.15). Every
  request in one endpoint's sequence carries the same unique query, so which is
  the warm-up, the confirm and each interval probe is recovered from their
  order, not from a remembered list.
- **`_reading()` is the one parser both halves call** (§0.12): `run()` for the
  `cache_ttl` output, `grade()` over the stored copies.

**Fixed**: the discriminator is derived from the endpoint
path, so there is no `observations:` map and `grade()` places the severity.
Confidence is where the split pays, because a timing-only cache signal is weak:
a fast second response is **not-proof-of-cache** — an LLM at temperature 0, a
warmed connection pool or a shorter generation all produce one, and no cache
header need corroborate it.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import asyncio
import hashlib
import time
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# TTL test intervals in seconds
TTL_TEST_INTERVALS = [5, 15, 30, 60]

# The recorded second response is a cache hit when it is meaningfully faster
# than the first. Kept as the original 0.7 factor.
_HIT_FACTOR = 0.7


class TTLMappingCheck(ServiceIteratingCheck):
    """
    Map cache TTL and expiry behavior to assess poisoning exposure windows.

    Sends a unique query, confirms it is cached via timing analysis, then
    re-queries at increasing intervals to detect when the cache entry
    expires. Compares observed TTL with cache header values.
    """

    name = "cag_ttl_mapping"
    description = "Map cache TTL and expiry behavior to assess poisoning exposure windows"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["cache_ttl"]
    service_types = ["ai", "api", "http"]

    reason = "Long cache TTL increases the exposure window for cache poisoning attacks and stale context exploitation"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["TTL analysis", "timing analysis", "cache header inspection"]

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
        ttl_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    path = endpoint.get("path", "unknown")
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"ttl-{path.strip('/').replace('/', '-')}",
                        target=service,
                        target_url=url,
                    )
                    await self._map_ttl(client, url, service, scan_id, candidate)
                    result.candidates.append(candidate)

                    reading = self._reading(candidate.exchanges)
                    if reading:
                        reading["url"] = url
                        ttl_results.append(reading)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if ttl_results:
            result.outputs["cache_ttl"] = ttl_results

        return result

    async def _map_ttl(
        self,
        client: AsyncHttpClient,
        url: str,
        service: Service,
        scan_id: str,
        candidate,
    ) -> None:
        """Drive the timing sequence, recording each request as an exchange.

        The control flow (early exits, breaking on the first cache miss) is the
        original's, decided on the exchange just recorded (§6.2) so `grade()`
        re-derives the same reading from the same bytes.
        """
        unique_id = hashlib.md5(f"{time.time()}_{url}".encode()).hexdigest()[:12]
        unique_query = f"ttl_mapping_test_{unique_id}"
        body = {"input": unique_query, "query": unique_query}

        # First request: establish cache entry (cache miss).
        ex1 = await self._send(client, url, body, scan_id, service.host)
        candidate.attach(ex1)
        if ex1 is None or ex1.error or (ex1.response_status or 0) >= 400:
            return
        time1 = ex1.elapsed_ms or 0.0

        # Second request: confirm caching (should be a cache hit).
        ex2 = await self._send(client, url, body, scan_id, service.host)
        candidate.attach(ex2)
        if ex2 is None or ex2.error:
            return
        time2 = ex2.elapsed_ms or 0.0

        if not (time1 > 0 and time2 < time1 * _HIT_FACTOR):
            return  # No caching detected — nothing more to probe.

        # Test at increasing intervals to find the TTL.
        last_hit_interval = 0
        for interval in TTL_TEST_INTERVALS:
            await asyncio.sleep(interval - last_hit_interval)
            ex = await self._send(client, url, body, scan_id, service.host)
            candidate.attach(ex)
            if ex is None or ex.error:
                break
            elapsed = ex.elapsed_ms or 0.0
            if elapsed < time1 * _HIT_FACTOR:
                last_hit_interval = interval
            else:
                break  # Cache miss: this interval is the observed TTL.

    async def _send(
        self, client: AsyncHttpClient, url: str, body: dict, scan_id: str, host: str
    ) -> Exchange | None:
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
        ttl_info = self._reading(list(evidence))
        if not ttl_info:
            return []
        ttl_info["url"] = ctx.target_url or ttl_info.get("url", "")

        severity = self._determine_severity(ttl_info)
        confidence, why = self._confidence(ttl_info)
        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                title=self._build_title(ttl_info),
                description=self._build_description(ttl_info),
                evidence=self._build_evidence(ttl_info),
                reasoning=why,
                signals={
                    "observed_ttl_seconds": ttl_info.get("observed_ttl_seconds"),
                    "header_ttl_seconds": ttl_info.get("header_ttl_seconds"),
                    "ttl_unbounded": ttl_info.get("ttl_unbounded"),
                    "ttl_mismatch": ttl_info.get("ttl_mismatch"),
                },
                references=self.references,
                raw_data=ttl_info,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    @staticmethod
    def _confidence(ttl_info: dict) -> tuple[float, str]:
        header_ttl = ttl_info.get("header_ttl_seconds")
        if ttl_info.get("ttl_mismatch"):
            return 0.7, (
                "two independent signals disagree — a cache header states a TTL and the "
                "observed expiry differs — which is itself the finding; the observed side "
                "still rests on timing, but the header corroborates that a cache exists"
            )
        if header_ttl is not None:
            return 0.65, (
                "a cache header states the TTL, so a cache is corroborated beyond timing; the "
                "exact expiry boundary is still inferred from response speed at coarse intervals"
            )
        return 0.4, (
            "the only signal is that a repeated query came back faster; an LLM at temperature 0, "
            "a warmed connection pool or a shorter generation all produce that without any cache, "
            "and no cache header corroborates it"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict | None:
        """Rebuild `_map_ttl`'s result off the recorded exchanges, in order.

        The warm-up pair is the first two exchanges; the interval probes are the
        rest, paired with `TTL_TEST_INTERVALS` by position. Returns `None` for
        anything the original returned `None` for: a failed first request or no
        caching detected.
        """
        if len(exchanges) < 2:
            return None
        ex1, ex2 = exchanges[0], exchanges[1]
        if ex1.error or (ex1.response_status or 0) >= 400 or ex2.error:
            return None

        time1 = ex1.elapsed_ms or 0.0
        time2 = ex2.elapsed_ms or 0.0
        if not (time1 > 0 and time2 < time1 * _HIT_FACTOR):
            return None

        header_ttl = self._extract_header_ttl(ex1.response_headers or {})
        speedup = (time1 - time2) / time1 if time1 > 0 else 0

        observed_ttl = None
        last_hit_interval = 0
        for interval, ex in zip(TTL_TEST_INTERVALS, exchanges[2:]):
            if ex.error:
                break
            elapsed = ex.elapsed_ms or 0.0
            if elapsed < time1 * _HIT_FACTOR:
                last_hit_interval = interval
            else:
                observed_ttl = interval
                break

        return {
            "caching_detected": True,
            "initial_request_ms": round(time1, 2),
            "cached_request_ms": round(time2, 2),
            "speedup_ratio": round(speedup, 2),
            "header_ttl_seconds": header_ttl,
            "observed_ttl_seconds": observed_ttl,
            "last_cache_hit_interval": last_hit_interval,
            "ttl_unbounded": observed_ttl is None,
            "ttl_mismatch": (
                header_ttl is not None
                and observed_ttl is not None
                and abs(header_ttl - observed_ttl) > 10
            ),
        }

    def _extract_header_ttl(self, headers: dict) -> int | None:
        """Extract TTL from cache-related response headers."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check Cache-Control: max-age
        cache_control = headers_lower.get("cache-control", "")
        if "max-age=" in cache_control:
            try:
                max_age = int(cache_control.split("max-age=")[1].split(",")[0].strip())
                return max_age
            except (ValueError, IndexError):
                pass

        # Check Expires header (simplified — just detect presence)
        if "expires" in headers_lower:
            return -1  # Present but not parsed to seconds

        # Check Age header
        age = headers_lower.get("age")
        if age:
            try:
                return int(age)
            except ValueError:
                pass

        return None

    def _determine_severity(self, ttl_info: dict) -> str:
        """Determine observation severity based on TTL."""
        if ttl_info.get("ttl_unbounded"):
            return "medium"
        if ttl_info.get("ttl_mismatch"):
            return "low"

        observed = ttl_info.get("observed_ttl_seconds")
        if observed and observed > 300:
            return "medium"
        if observed:
            return "info"

        header_ttl = ttl_info.get("header_ttl_seconds")
        if header_ttl and header_ttl > 300:
            return "medium"

        return "low"

    def _build_title(self, ttl_info: dict) -> str:
        """Build observation title."""
        if ttl_info.get("ttl_unbounded"):
            return "Unbounded cache TTL (no expiry detected within test window)"
        if ttl_info.get("ttl_mismatch"):
            return (
                f"Cache TTL mismatch: header says {ttl_info['header_ttl_seconds']}s "
                f"but observed {ttl_info['observed_ttl_seconds']}s"
            )
        observed = ttl_info.get("observed_ttl_seconds")
        if observed:
            return f"Cache TTL: {observed}s"
        return "Cache TTL detected via headers"

    def _build_description(self, ttl_info: dict) -> str:
        """Build observation description."""
        parts = []

        if ttl_info.get("ttl_unbounded"):
            parts.append(
                f"Cache entries did not expire within the test window "
                f"(last cache hit at {ttl_info['last_cache_hit_interval']}s). "
                f"Long-lived or indefinite caching increases the exposure window "
                f"for cache poisoning attacks."
            )
        elif ttl_info.get("observed_ttl_seconds"):
            ttl = ttl_info["observed_ttl_seconds"]
            risk = "high" if ttl > 300 else "moderate" if ttl > 60 else "low"
            parts.append(f"Cache TTL observed at approximately {ttl} seconds ({risk} risk). ")

        if ttl_info.get("ttl_mismatch"):
            parts.append(
                f"TTL mismatch detected: headers state {ttl_info['header_ttl_seconds']}s "
                f"but actual expiry observed at {ttl_info['observed_ttl_seconds']}s."
            )

        return " ".join(parts) if parts else "Cache TTL detected."

    def _build_evidence(self, ttl_info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Initial request: {ttl_info['initial_request_ms']}ms",
            f"Cached request: {ttl_info['cached_request_ms']}ms",
            f"Speedup: {ttl_info['speedup_ratio']:.0%}",
        ]
        if ttl_info.get("header_ttl_seconds") is not None:
            lines.append(f"Header TTL: {ttl_info['header_ttl_seconds']}s")
        if ttl_info.get("observed_ttl_seconds") is not None:
            lines.append(f"Observed TTL: {ttl_info['observed_ttl_seconds']}s")
        if ttl_info.get("ttl_unbounded"):
            lines.append(f"TTL unbounded: cache hit at {ttl_info['last_cache_hit_interval']}s")
        return "\n".join(lines)
