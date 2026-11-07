"""
app/checks/cag/cache_poisoning.py - Cache Poisoning with Malicious Content

Test if injected content gets cached and served to other users.
This is the actual attack — not just detection of caching behavior.

Attack vectors:
- Inject marker into query, verify it's cached and served cross-session
- Semantic cache poisoning: similar queries also serve poisoned response
- Single injection affects all users until cache expires

**Probe/grade.** The probe runs the exact-replay poisoning
test (inject from one session, read from another) and the semantic sweep, records
every request, and hands over one candidate per endpoint. `grade()` re-reads the
recorded requests, recovers each test and its random marker from the request
body, and returns the verdicts. Conventions this check contributes:

- **Each test and its marker are recovered from the recorded request** (§0.16):
  the exact-replay query carries `CACHE_POISON_MARKER_<hex>` and the semantic
  probes `SEMANTIC_POISON_<hex>`, both read back so `grade()` matches the same
  marker against the same responses without a remembered list.
- **The two exact-replay requests are paired by recorded order** (§0.15): they
  carry byte-identical bodies (only `X-Session-Id` differs), so the first is the
  injection and the second the cross-session read.
- **Timing is read back, not re-measured** (§0.12): the `likely_cached` signal
  takes the cross-session request's `elapsed_ms` off the record.
- **Cleanup requests are ignored on read-back** (§0.15).

**Contextual**: whether injected content is really served to
another user is a judgement, so severity is the grader's (the planned LLM tier); the rule
tier keeps the original severities and states its weakness in the confidence —
**the marker is the instructed output** the model was asked to echo, so its
reappearance is compliance-shaped rather than proof of a stored poisoning, and a
fast, identical cross-session response is what a deterministic model returns with
no cache at all.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
  MITRE ATLAS - AML.T0048 Data Poisoning
"""

import asyncio
import contextlib
import json
import re
import uuid
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

_EXACT_PREFIX = "CACHE_POISON_MARKER_"
_SEMANTIC_PREFIX = "SEMANTIC_POISON_"

# The semantic sweep's benign variations, so grade() can tell them from the
# poison query when re-reading.
_SEMANTIC_VARIATIONS = [
    "What's the capital of France?",
    "Tell me France's capital city",
    "Capital of France?",
]


class CachePoisoningCheck(ServiceIteratingCheck):
    """
    Test if injected content gets cached and served to other users.

    Sends a query with a unique injection marker, waits for cache
    population, then queries from a different session context to check
    if the poisoned response is served cross-session.
    """

    name = "cag_cache_poisoning"
    description = "Test if injected content gets cached and served to other users"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["cache_poisoning_results"]
    service_types = ["ai", "api", "http"]

    reason = "Cache poisoning is the highest-impact CAG attack — one injection persists for all users who trigger the same cache key"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "MITRE ATLAS - AML.T0048 Data Poisoning",
    ]
    techniques = ["cache poisoning", "cross-session verification", "semantic poisoning"]

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

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator="poison-exact",
                        target=service,
                        target_url=url,
                    )
                    await self._test_exact(client, url, scan_id, service.host, candidate)
                    await self._test_semantic(client, url, scan_id, service.host, candidate)
                    await self._attempt_cleanup(client, service, scan_id, candidate, context)

                    result.candidates.append(candidate)
                    reading = self._reading(candidate.exchanges)
                    if reading:
                        result.outputs.setdefault("cache_poisoning_results", []).extend(reading)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    async def _test_exact(self, client, url, scan_id, host, candidate) -> None:
        marker = f"{_EXACT_PREFIX}{uuid.uuid4().hex[:12]}"
        poison_query = f"What is the capital of France? [{marker}]"
        body = {"input": poison_query, "query": poison_query}

        ex1 = await self._send(
            client,
            url,
            body,
            scan_id,
            host,
            candidate,
            {**JSON_HEADERS, "X-Session-Id": f"poison-session-a-{uuid.uuid4().hex[:6]}"},
        )
        if ex1 is None or ex1.error or (ex1.response_status or 0) >= 400:
            return
        await asyncio.sleep(2)
        await self._send(
            client,
            url,
            body,
            scan_id,
            host,
            candidate,
            {**JSON_HEADERS, "X-Session-Id": f"poison-session-b-{uuid.uuid4().hex[:6]}"},
        )

    async def _test_semantic(self, client, url, scan_id, host, candidate) -> None:
        marker = f"{_SEMANTIC_PREFIX}{uuid.uuid4().hex[:12]}"
        poison_query = f"What is the capital of France? [{marker}]"

        ex1 = await self._send(
            client,
            url,
            {"input": poison_query, "query": poison_query},
            scan_id,
            host,
            candidate,
            {**JSON_HEADERS, "X-Session-Id": f"semantic-poison-{uuid.uuid4().hex[:6]}"},
        )
        if ex1 is None or ex1.error or (ex1.response_status or 0) >= 400:
            return
        await asyncio.sleep(2)
        for variation in _SEMANTIC_VARIATIONS:
            await self._send(
                client,
                url,
                {"input": variation, "query": variation},
                scan_id,
                host,
                candidate,
                {**JSON_HEADERS, "X-Session-Id": f"semantic-check-{uuid.uuid4().hex[:6]}"},
            )

    async def _attempt_cleanup(self, client, service, scan_id, candidate, context) -> None:
        """Attempt to clean up poisoned cache entries. Recorded but not graded."""
        eviction = context.get("eviction_capability", [])
        for ev in eviction if isinstance(eviction, list) else []:
            if ev.get("accessible"):
                cleanup_url = ev.get("url", "")
                with contextlib.suppress(Exception):
                    await self._send(
                        client,
                        cleanup_url,
                        {},
                        scan_id,
                        service.host,
                        candidate,
                        dict(JSON_HEADERS),
                    )
        for path in ["/cache/clear", "/cache/invalidate"]:
            with contextlib.suppress(Exception):
                await self._send(
                    client,
                    service.with_path(path),
                    {},
                    scan_id,
                    service.host,
                    candidate,
                    dict(JSON_HEADERS),
                )

    async def _send(self, client, url, body, scan_id, host, candidate, headers) -> Exchange | None:
        resp = await client.post(url, json=body, headers=headers)
        ex = exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="POST",
            request_headers=headers,
            request_json=body,
        )
        candidate.attach(ex)
        return ex

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        readings = self._reading(list(evidence))
        verdicts: list[Verdict] = []
        for reading in readings:
            if reading.get("test_id") == "semantic_poisoning":
                n = reading.get("variations_poisoned", 0)
                verdicts.append(
                    Verdict(
                        severity="critical",
                        confidence=0.4,
                        discriminator="poison-semantic",
                        title=f"Semantic cache amplifies poisoning: {n} query variations affected",
                        description=self._build_description(reading),
                        evidence=self._build_evidence(reading),
                        reasoning=(
                            "the poison marker reappeared in responses to benign, semantically "
                            "similar queries — a strong amplification signal — but the marker is a "
                            "substring the query asked the model to echo, so a coincidental echo and "
                            "a semantic cache hit are indistinguishable at the rule tier"
                        ),
                        references=self.references,
                        raw_data=reading,
                        tier=ctx.tier,
                        evidence_ids=evidence.ids(),
                    )
                )
                continue

            severity = self._determine_severity(reading)
            confidence, why = self._confidence(reading)
            verdicts.append(
                Verdict(
                    severity=severity,
                    confidence=confidence,
                    discriminator="poison-exact",
                    title=self._build_title(reading),
                    description=self._build_description(reading),
                    evidence=self._build_evidence(reading),
                    reasoning=why,
                    signals={
                        "marker_in_cross_session": reading.get("marker_in_cross_session"),
                        "responses_match": reading.get("responses_match"),
                        "likely_cached": reading.get("likely_cached"),
                    },
                    references=self.references,
                    raw_data=reading,
                    tier=ctx.tier,
                    evidence_ids=evidence.ids(),
                )
            )
        return verdicts

    @staticmethod
    def _confidence(reading: dict) -> tuple[float, str]:
        if reading.get("marker_in_cross_session"):
            return 0.4, (
                "the injected marker appeared in a second session's response, which looks like "
                "poisoning — but the query asked the model to include the marker, so its presence "
                "is compliance with the prompt, not proof the response came from a shared cache"
            )
        if reading.get("responses_match") and reading.get("likely_cached"):
            return 0.35, (
                "the two sessions got byte-identical responses and the second came back fast — but "
                "a deterministic model returns identical text to a repeated query without any "
                "cache, and 'fast' has no uncached baseline to compare against here"
            )
        return 0.3, (
            "the signal is a fast cross-session response with no marker echo; timing alone, with "
            "no uncached baseline, does not establish a cache let alone a poisoned one"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> list[dict]:
        """Rebuild the exact and semantic poisoning results off the record."""
        results = []

        exact = [ex for ex in exchanges if self._prefix_in(ex, _EXACT_PREFIX)]
        exact_reading = self._exact_reading(exact)
        if exact_reading:
            results.append(exact_reading)

        semantic_reading = self._semantic_reading(exchanges)
        if semantic_reading and semantic_reading.get("poisoning_detected"):
            results.append(semantic_reading)

        return results

    def _exact_reading(self, exact: list[Exchange]) -> dict | None:
        """The exact-replay result. Always reported when the first request
        succeeded, matching the original's unconditional `if exact_result`."""
        if not exact:
            return None
        first = exact[0]
        marker = self._marker_of(first, _EXACT_PREFIX)
        if first.error or (first.response_status or 0) >= 400:
            return None  # original returned an error dict; no observation of value

        poison_response = first.response_body or ""
        poison_query = self._query_of(first)

        if len(exact) < 2 or exact[1].error:
            # Cross-session request failed or absent; original returned an error
            # dict that still produced an observation at info severity.
            return {
                "test_id": "exact_poisoning",
                "poisoning_detected": False,
                "marker": marker,
                "poison_query": poison_query,
            }

        second = exact[1]
        cross_response = second.response_body or ""
        cross_session_ms = round(second.elapsed_ms or 0.0, 2)

        marker_found = marker in cross_response
        responses_match = poison_response == cross_response and len(poison_response) > 50
        likely_cached = cross_session_ms < 1000
        poisoning_confirmed = marker_found or (responses_match and likely_cached)

        return {
            "test_id": "exact_poisoning",
            "poisoning_detected": poisoning_confirmed,
            "marker": marker,
            "marker_in_cross_session": marker_found,
            "responses_match": responses_match,
            "cross_session_ms": cross_session_ms,
            "likely_cached": likely_cached,
            "poison_query": poison_query,
            "poison_response_preview": poison_response[:200],
            "cross_response_preview": cross_response[:200],
        }

    def _semantic_reading(self, exchanges: list[Exchange]) -> dict | None:
        poison = [ex for ex in exchanges if self._prefix_in(ex, _SEMANTIC_PREFIX)]
        if not poison:
            return None
        first = poison[0]
        if first.error or (first.response_status or 0) >= 400:
            return None
        marker = self._marker_of(first, _SEMANTIC_PREFIX)
        poison_body = first.response_body or ""

        variations = [ex for ex in exchanges if self._query_of(ex) in _SEMANTIC_VARIATIONS]
        variations_poisoned = 0
        variation_results = []
        for ex in variations:
            if ex.error:
                continue
            response_body = ex.response_body or ""
            is_poisoned = marker in response_body or response_body == poison_body
            if is_poisoned:
                variations_poisoned += 1
            variation_results.append({"query": self._query_of(ex), "poisoned": is_poisoned})

        return {
            "test_id": "semantic_poisoning",
            "poisoning_detected": variations_poisoned > 0,
            "marker": marker,
            "variations_tested": len(variations),
            "variations_poisoned": variations_poisoned,
            "variation_results": variation_results,
        }

    def _prefix_in(self, exchange: Exchange, prefix: str) -> bool:
        return prefix in self._query_of(exchange)

    @staticmethod
    def _query_of(exchange: Exchange) -> str:
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return ""
        if not isinstance(body, dict):
            return ""
        value = body.get("query")
        return value if isinstance(value, str) else ""

    def _marker_of(self, exchange: Exchange, prefix: str) -> str:
        match = re.search(rf"{prefix}[0-9a-f]+", self._query_of(exchange))
        return match.group(0) if match else ""

    def _determine_severity(self, poison_result: dict) -> str:
        """Determine observation severity."""
        if poison_result.get("poisoning_detected"):
            if poison_result.get("marker_in_cross_session"):
                return "critical"
            if poison_result.get("responses_match") and poison_result.get("likely_cached"):
                return "high"
            return "high"

        if poison_result.get("likely_cached"):
            return "medium"

        return "info"

    def _build_title(self, poison_result: dict) -> str:
        """Build observation title."""
        if poison_result.get("marker_in_cross_session"):
            return "Cache poisoning confirmed: injected content served to different session"
        if poison_result.get("poisoning_detected"):
            return "Cache poisoning possible: injected content cached and responses match cross-session"
        if poison_result.get("likely_cached"):
            return "Cache accepts arbitrary content but cross-session delivery not confirmed"
        return (
            "Cache poisoning not possible: injected content not cached or not served cross-session"
        )

    def _build_description(self, poison_result: dict) -> str:
        """Build observation description."""
        test_id = poison_result.get("test_id", "")

        if test_id == "semantic_poisoning" and poison_result.get("poisoning_detected"):
            n = poison_result.get("variations_poisoned", 0)
            return (
                f"Semantic cache amplifies poisoning: the poisoned response was served "
                f"to {n} semantically similar query variations. This means a single "
                f"poisoning attack can affect a wide range of user queries."
            )

        if poison_result.get("marker_in_cross_session"):
            return (
                "Cache poisoning confirmed: an injected marker was found in the response "
                "served to a different session. Every subsequent user who triggers the "
                "same cache key will receive the attacker's content."
            )
        if poison_result.get("poisoning_detected"):
            return (
                "Cache poisoning likely: the cached response matches across sessions, "
                "indicating injected content persists in the cache."
            )
        return "Cache poisoning was not confirmed in this test."

    def _build_evidence(self, poison_result: dict) -> str:
        """Build evidence string."""
        lines = [f"Test: {poison_result.get('test_id', 'unknown')}"]

        if poison_result.get("marker"):
            lines.append(f"Marker: {poison_result['marker']}")
        if poison_result.get("poison_query"):
            lines.append(f"Poison query: {poison_result['poison_query'][:80]}")
        if "marker_in_cross_session" in poison_result:
            lines.append(f"Marker in cross-session: {poison_result['marker_in_cross_session']}")
        if poison_result.get("cross_session_ms"):
            lines.append(f"Cross-session response time: {poison_result['cross_session_ms']}ms")
        if poison_result.get("variations_poisoned"):
            lines.append(
                f"Semantic variations poisoned: "
                f"{poison_result['variations_poisoned']}/{poison_result.get('variations_tested', '?')}"
            )

        return "\n".join(lines)
