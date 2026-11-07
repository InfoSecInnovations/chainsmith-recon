"""
app/checks/rag/cache_poisoning.py - RAG Cache Poisoning Detection

Test if the RAG caches query results. If a poisoned response gets
cached, it affects all subsequent users with the same query.

Detection:
  - Compare repeated identical queries for response consistency
  - Check cache-related headers (Cache-Control, Age, X-Cache, ETag)
  - Timing analysis (cached responses are faster)

**Probe/grade.** The probe sends each query twice and records
all four exchanges; `grade()` re-reads them and returns one verdict.
`_reading()` is the one parser both halves call (§0.12), and three things it does
are the conventions this check contributes:

- **Timing is read back, not re-measured.** The original timed the two requests
  with `time.monotonic()` around the await. That number cannot be reproduced from
  a corpus, so the reading takes `Exchange.elapsed_ms` instead and a re-grade
  reaches the same conclusion about the same pair of requests.
- **The repeat request is identified by its own headers.** The second request of
  each pair carries `Cache-Control: no-cache` and the first does not, so which is
  which is recovered from the recorded request rather than from loop position.
- **Whether injection was already found is read at grade time** off
  `GradeContext.context` (`vulnerable_rag_endpoints`), not stamped during the
  probe — the same rule `agent_cross_injection` follows (§0.15).

**Fixed**: the discriminators are a closed four-value set,
so the contract carries the full `observations:` map. Confidence is where the
split pays, because both signals are weaker than the titles suggest: an LLM
pipeline at temperature 0 returns identical text for a repeated query *without*
any cache, and `Cache-Control` is emitted by nearly every HTTP stack — including
as `no-store`, which this check counts as a cache indicator.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}
REPEAT_HEADERS = {"Content-Type": "application/json", "Cache-Control": "no-cache"}

CACHE_HEADERS = [
    "cache-control",
    "age",
    "x-cache",
    "x-cache-hit",
    "etag",
    "last-modified",
    "x-cached",
    "cf-cache-status",
    "x-varnish",
]

TEST_QUERIES = [
    "What is the most common topic in this knowledge base?",
    "Summarize the primary document categories",
]


class RAGCachePoisoningCheck(ServiceIteratingCheck):
    """
    Detect RAG-level response caching and assess cache poisoning risk.
    """

    name = "rag_cache_poisoning"
    description = "Detect RAG response caching and assess cache poisoning risk"

    conditions = [CheckCondition("rag_endpoints", "truthy")]
    produces = ["rag_cache_behavior"]
    service_types = ["ai", "api", "http"]

    reason = (
        "If RAG caches poisoned responses, the attack affects all subsequent "
        "users submitting the same or similar query — not just the attacker"
    )
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
        "CWE-524 Use of Cache Containing Sensitive Information",
    ]
    techniques = ["cache detection", "response timing analysis", "cache poisoning"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        rag_endpoints = context.get("rag_endpoints", [])
        service_endpoints = [
            ep
            for ep in rag_endpoints
            if ep.get("service", {}).get("host") == service.host
            and ep.get("endpoint_type") == "rag_query"
        ]
        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        ep = service_endpoints[0]
        url = ep.get("url", service.url)
        candidate = self.create_candidate(host=service.host, target=service, target_url=url)

        try:
            async with AsyncHttpClient(cfg) as client:
                for query in TEST_QUERIES:
                    body = self._request_body(query)

                    # First request.
                    resp1 = await client.post(url, json=body, headers=JSON_HEADERS)
                    candidate.attach(self._record(resp1, scan_id, service.host, body, JSON_HEADERS))
                    if resp1.error or resp1.status_code >= 400:
                        continue

                    # Second request: identical body, different "session".
                    resp2 = await client.post(url, json=body, headers=REPEAT_HEADERS)
                    candidate.attach(
                        self._record(resp2, scan_id, service.host, body, REPEAT_HEADERS)
                    )
                    if resp2.error or resp2.status_code >= 400:
                        continue

                    # Decided on the two exchanges just recorded (§6.2), so
                    # `grade()` re-derives the same early exit from the same bytes.
                    reading = self._reading(candidate.exchanges)
                    if reading["caching_detected"]:
                        break

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # One candidate per service: every discriminator describes this one
        # endpoint's caching behaviour, and the check emits exactly one. Appended
        # even when every request failed, because "no caching detected" has
        # always been a reported answer.
        result.candidates.append(candidate)
        result.outputs["rag_cache_behavior"] = self._reading(candidate.exchanges)
        return result

    def _record(
        self, resp, scan_id: str, host: str, body: dict, headers: dict[str, str]
    ) -> Exchange:
        return exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="POST",
            request_headers=headers,
            request_json=body,
        )

    @staticmethod
    def _request_body(query: str) -> dict:
        return {"query": query, "question": query, "input": query}

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        behavior = self._reading(list(evidence))
        ids = evidence.ids()

        if not behavior["caching_detected"]:
            answered = [e for e in evidence if self._usable(e)]
            return [
                Verdict(
                    severity="info",
                    confidence=0.5 if answered else 0.2,
                    discriminator="no-cache",
                    title="No RAG-level caching detected",
                    description="No caching indicators found in RAG responses.",
                    evidence="No cache headers or response duplication detected",
                    reasoning=(
                        "neither repeated query returned the same bytes twice and no cache header "
                        "was set; a cache keyed on a session or user id would be invisible to this "
                        "test, which repeats the query on the same client"
                        if answered
                        else "no request produced a usable response, so this is the absence of "
                        "evidence rather than evidence of absence"
                    ),
                    signals={"responses_read": len(answered)},
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        headers = behavior["cache_headers"]
        identical = behavior["identical_responses"]
        # Whether injection was already found on this endpoint is scan context,
        # read here rather than stamped during the probe (§0.15).
        has_injection = bool((ctx.context or {}).get("vulnerable_rag_endpoints"))

        if has_injection and identical:
            return [
                Verdict(
                    severity="high",
                    confidence=0.4,
                    discriminator="cache-poisoned",
                    title="RAG cache poisoning: injected response served to subsequent queries",
                    description=(
                        "RAG caches responses and indirect injection was detected on "
                        "this endpoint. Cached poisoned responses affect all users."
                    ),
                    evidence=self._build_evidence(behavior),
                    reasoning=(
                        "two facts are solid — a repeated query returned byte-identical text, and "
                        "another check found injection on this endpoint — but the join between "
                        "them is inferred. No poisoned response was observed being served from "
                        "cache to a second party, and identical text is also what deterministic "
                        "generation produces with no cache at all"
                    ),
                    signals={
                        "cache_headers": list(headers),
                        "identical_responses": True,
                        "injection_previously_found": True,
                    },
                    references=self.references,
                    raw_data=behavior,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        if identical:
            if headers:
                confidence, why = (
                    0.75,
                    (
                        "a repeated query returned byte-identical text *and* the response advertises "
                        f"cache state ({', '.join(sorted(headers))}) — two independent signals "
                        "agreeing"
                    ),
                )
            else:
                confidence, why = (
                    0.4,
                    (
                        "the only signal is that a repeated query returned byte-identical text, and "
                        "an LLM pipeline at temperature 0 does that without any cache; no cache "
                        "header corroborates it"
                    ),
                )
            return [
                Verdict(
                    severity="medium",
                    confidence=confidence,
                    discriminator="cache-detected",
                    title="RAG caching detected: identical responses to repeated queries",
                    description=(
                        f"Identical responses returned for repeated queries. "
                        f"Cache headers: {headers or 'none'}."
                    ),
                    evidence=self._build_evidence(behavior),
                    reasoning=why,
                    signals={
                        "cache_headers": list(headers),
                        "identical_responses": True,
                        "timing_suggests_cache": behavior["timing_suggests_cache"],
                    },
                    references=self.references,
                    raw_data=behavior,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        return [
            Verdict(
                severity="low",
                confidence=0.3,
                discriminator="cache-varied",
                title="RAG caching detected but responses vary",
                description="Cache headers present but responses differ — may use session keys.",
                evidence=self._build_evidence(behavior),
                reasoning=(
                    "rests entirely on a cache-related header being present, and this check counts "
                    f"any of {', '.join(sorted(headers))} — `Cache-Control` is emitted by nearly "
                    "every HTTP stack, including as `no-store`, and `ETag` / `Last-Modified` are "
                    "routine. The responses themselves differed, which argues against a cache"
                ),
                signals={
                    "cache_headers": list(headers),
                    "identical_responses": False,
                },
                raw_data=behavior,
                tier=ctx.tier,
                evidence_ids=ids,
            )
        ]

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict[str, Any]:
        """Rebuild the caching reading off the recorded exchanges.

        Walks `TEST_QUERIES` in order and pairs each query's two requests by
        their recorded `Cache-Control` header, replicating the original loop —
        including that the first response's cache headers are kept even when the
        repeat request fails.
        """
        behavior: dict[str, Any] = {
            "caching_detected": False,
            "cache_headers": {},
            "identical_responses": False,
            "timing_suggests_cache": False,
        }

        for query in TEST_QUERIES:
            first, repeat = self._pair_for(exchanges, query)
            if first is None or not self._usable(first):
                continue
            self._collect_headers(first, behavior)

            if repeat is None or not self._usable(repeat):
                continue
            self._collect_headers(repeat, behavior)

            body1 = first.response_body or ""
            body2 = repeat.response_body or ""
            if body1 and body2 and body1 == body2:
                behavior["identical_responses"] = True

            # Timing off the record, not a re-measured await.
            t1, t2 = first.elapsed_ms, repeat.elapsed_ms
            if t1 is not None and t2 is not None and t1 > 500 and t2 < t1 * 0.5:
                behavior["timing_suggests_cache"] = True
                behavior["timing"] = {"first_ms": int(t1), "second_ms": int(t2)}

            if behavior["identical_responses"] or behavior["cache_headers"]:
                behavior["caching_detected"] = True
                break

        return behavior

    @staticmethod
    def _collect_headers(exchange: Exchange, behavior: dict) -> None:
        resp_hdrs = {k.lower(): v for k, v in (exchange.response_headers or {}).items()}
        for hdr in CACHE_HEADERS:
            if hdr in resp_hdrs:
                behavior["cache_headers"][hdr] = resp_hdrs[hdr]

    def _pair_for(
        self, exchanges: list[Exchange], query: str
    ) -> tuple[Exchange | None, Exchange | None]:
        """This query's first and repeat exchange, told apart by their own headers.

        The two requests carry identical bodies; only the repeat sets
        `Cache-Control: no-cache`. Reading that off the recorded request is what
        keeps the pair identifiable without trusting the order they arrived in.
        """
        first = repeat = None
        for exchange in exchanges:
            if self._query_of(exchange) != query:
                continue
            headers = {k.lower(): v for k, v in (exchange.request_headers or {}).items()}
            if "cache-control" in headers:
                repeat = repeat or exchange
            else:
                first = first or exchange
        return first, repeat

    @staticmethod
    def _query_of(exchange: Exchange) -> str:
        """Which query this exchange asked, off its recorded request body."""
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return ""
        if not isinstance(body, dict):
            return ""
        value = body.get("query")
        return value if isinstance(value, str) else ""

    @staticmethod
    def _usable(exchange: Exchange) -> bool:
        """The original skipped errors and 4xx/5xx before reading anything."""
        return not exchange.error and (exchange.response_status or 0) < 400

    def _build_evidence(self, behavior: dict) -> str:
        lines = []
        if behavior["cache_headers"]:
            lines.append(f"Cache headers: {behavior['cache_headers']}")
        lines.append(f"Identical responses: {behavior['identical_responses']}")
        lines.append(f"Timing suggests cache: {behavior['timing_suggests_cache']}")
        if "timing" in behavior:
            lines.append(
                f"Timing: {behavior['timing']['first_ms']}ms -> {behavior['timing']['second_ms']}ms"
            )
        return "\n".join(lines)
