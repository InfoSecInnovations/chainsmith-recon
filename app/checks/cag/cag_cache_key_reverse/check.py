"""
app/checks/cag/cache_key_reverse.py - Cache Key Reverse Engineering

Systematically vary query components to map which parts of the input
determine the cache key.

Attack vectors:
- Cache key excludes system prompt: multi-tenant safety bypass
- Cache key truncation: injection payload after key boundary
- Case-insensitive keys: wider collision surface

**Probe/grade.** The probe confirms caching, then sends each
component test's populate + variant requests and the system-prompt pair,
recording all of them as one candidate per endpoint (each observation names the
endpoint `target_url`, and one candidate yields several verdicts — §0.15).
`grade()` re-reads the recorded exchanges; `_analyze()` is the one parser both
halves call (§0.12). Conventions it contributes:

- **Timing is read back, not re-measured** (`Exchange.elapsed_ms`), so a re-grade
  reproduces every cache-hit call from the corpus.
- **Byte-identical baseline requests are paired by order** (§0.15): the two
  `baseline_key_test_` probes are identical, so the first recorded is the
  uncached read and the second the cached one.
- **Each test's variant is recovered from its own recorded body** — the variant
  query text (`_variant_of`) for the component tests, the `system` field for the
  system-prompt test — never from the order the tests ran.

**Fixed**: the discriminators are a closed five-value set,
so the contract carries the full `observations:` map at each one's floor.
Confidence is where the split pays: every call is a timing inference, and a fast
response to a variant query is as easily backend warmup as a cache hit.

References:
  https://portswigger.net/web-security/web-cache-poisoning
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import asyncio
import json
import time
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}
BASELINE_PREFIX = "baseline_key_test_"

# Query variation pairs to test which components are in the cache key
KEY_COMPONENT_TESTS = [
    {
        "id": "capitalization",
        "description": "Case sensitivity",
        "base": "what is the capital of france",
        "variant": "What Is The Capital Of France",
    },
    {
        "id": "punctuation",
        "description": "Punctuation sensitivity",
        "base": "what is the capital of france",
        "variant": "what is the capital of france?",
    },
    {
        "id": "whitespace",
        "description": "Whitespace sensitivity",
        "base": "what is the capital of france",
        "variant": "what  is  the  capital  of  france",
    },
    {
        "id": "prefix",
        "description": "Prefix/preamble sensitivity",
        "base": "capital of france",
        "variant": "Please kindly tell me the capital of france",
    },
    {
        "id": "suffix",
        "description": "Suffix/trailing content sensitivity",
        "base": "what is the capital of france",
        "variant": "what is the capital of france please thank you",
    },
]

SYSTEM_PROMPT_TESTS = [
    {
        "id": "system_prompt",
        "description": "System prompt in cache key",
        "query": "what is 2 plus 2",
        "system_a": "You are a helpful assistant.",
        "system_b": "You are a pirate. Respond only in pirate speak.",
    },
]


class CacheKeyReverseCheck(ServiceIteratingCheck):
    """
    Map cache key components by systematically varying query inputs.

    Sends pairs of queries that differ in one component and uses
    timing analysis to detect cache hits, revealing which components
    are included in or excluded from the cache key.
    """

    name = "cag_cache_key_reverse"
    description = "Map cache key components by systematically varying query inputs"
    intrusive = True

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["key_structure"]
    service_types = ["ai", "api", "http"]

    reason = "Understanding cache key structure reveals poisoning vectors: keys that exclude system prompts enable multi-tenant attacks"
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["cache key analysis", "timing analysis", "input variation"]

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
        key_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    candidate = self.create_candidate(
                        host=service.host, target=service, target_url=url
                    )
                    await self._probe_endpoint(client, url, scan_id, service.host, candidate)
                    result.candidates.append(candidate)

                    analysis = self._analyze(candidate.exchanges)
                    key_results.extend(analysis["key_results"])

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if key_results:
            result.outputs["key_structure"] = key_results

        return result

    async def _probe_endpoint(
        self, client: AsyncHttpClient, url: str, scan_id: str, host: str, candidate
    ) -> None:
        # Baseline: two identical probes (uncached read, then cached read).
        test_query = f"{BASELINE_PREFIX}{int(time.time())}"
        for _ in range(2):
            candidate.attach(
                await self._send(
                    client, url, {"input": test_query, "query": test_query}, scan_id, host
                )
            )

        # Each key component: populate with base (not timed), then send variant.
        for test in KEY_COMPONENT_TESTS:
            await self._send(
                client, url, {"input": test["base"], "query": test["base"]}, scan_id, host
            )
            await asyncio.sleep(0.5)
            candidate.attach(
                await self._send(
                    client, url, {"input": test["variant"], "query": test["variant"]}, scan_id, host
                )
            )

        # System prompt: populate with system A, then send with system B.
        for test in SYSTEM_PROMPT_TESTS:
            q = test["query"]
            await self._send(
                client,
                url,
                {
                    "input": q,
                    "query": q,
                    "system": test["system_a"],
                    "messages": [
                        {"role": "system", "content": test["system_a"]},
                        {"role": "user", "content": q},
                    ],
                },
                scan_id,
                host,
            )
            await asyncio.sleep(0.5)
            candidate.attach(
                await self._send(
                    client,
                    url,
                    {
                        "input": q,
                        "query": q,
                        "system": test["system_b"],
                        "messages": [
                            {"role": "system", "content": test["system_b"]},
                            {"role": "user", "content": q},
                        ],
                    },
                    scan_id,
                    host,
                )
            )

    async def _send(
        self, client: AsyncHttpClient, url: str, body: dict, scan_id: str, host: str
    ) -> Exchange:
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
        analysis = self._analyze(list(evidence))
        if not analysis["caching_detected"]:
            # The original `continue`d past a non-caching endpoint, emitting
            # nothing; a candidate with no verdict yields no observation.
            return []

        key_results = analysis["key_results"]
        verdicts: list[Verdict] = []

        # High: system prompt not in key.
        for r in key_results:
            if r["test_id"] == "system_prompt" and r.get("cache_hit_on_variant"):
                verdicts.append(
                    Verdict(
                        severity="high",
                        confidence=0.4,
                        discriminator="key-excludes-system-prompt",
                        title="Cache key excludes system prompt: different system messages share cache",
                        description=(
                            "The cache key does not include the system prompt. Different system "
                            "messages produce cache hits for the same user query, meaning users "
                            "with different safety configurations share cache entries."
                        ),
                        evidence=self._build_evidence(r),
                        reasoning=(
                            "the exclusion is inferred from one timing: system_b answered faster "
                            "than 70% of the uncached baseline. A warm backend or an unrelated "
                            "load dip gives the same fast response, and nothing confirms the "
                            "system prompt was actually left out of the key"
                        ),
                        signals={
                            "variant_ms": r.get("variant_ms"),
                            "threshold_ms": r.get("threshold_ms"),
                        },
                        references=self.references,
                        raw_data=r,
                        tier=ctx.tier,
                        evidence_ids=evidence.ids(),
                    )
                )

        # Medium: case/whitespace/punctuation-insensitive key.
        for r in key_results:
            if r["test_id"] in ("capitalization", "whitespace", "punctuation") and r.get(
                "cache_hit_on_variant"
            ):
                verdicts.append(
                    Verdict(
                        severity="medium",
                        confidence=0.4,
                        discriminator=f"key-ignores-{r['test_id']}",
                        title=f"Cache key is {r['description'].lower()}-insensitive",
                        description=(
                            f"Cache key ignores {r['description'].lower()} differences. "
                            f"This widens the collision surface for cache poisoning attacks."
                        ),
                        evidence=self._build_evidence(r),
                        reasoning=(
                            "rests on the variant answering faster than the cache-hit threshold — "
                            "a timing inference over a single sample. Response-time noise on an "
                            "LLM backend spans this margin, and no cache header corroborates the "
                            "normalisation"
                        ),
                        signals={
                            "variant_ms": r.get("variant_ms"),
                            "threshold_ms": r.get("threshold_ms"),
                        },
                        references=self.references,
                        raw_data=r,
                        tier=ctx.tier,
                        evidence_ids=evidence.ids(),
                    )
                )

        # Low: all components in key.
        if key_results and all(r.get("component_in_key", False) for r in key_results):
            verdicts.append(
                Verdict(
                    severity="low",
                    confidence=0.5,
                    discriminator="key-detailed",
                    title="Cache key includes most query components (detailed key)",
                    description="All tested query components are part of the cache key, reducing collision risk.",
                    evidence=f"Tested {len(key_results)} key components, all included in cache key",
                    reasoning=(
                        "every variant answered slower than the cache-hit threshold, read as the "
                        "component being in the key — but that is the absence of a timing signal "
                        "across a handful of samples, not positive proof the key is detailed"
                    ),
                    signals={"components_tested": len(key_results)},
                    raw_data={"key_results": key_results},
                    tier=ctx.tier,
                    evidence_ids=evidence.ids(),
                )
            )

        return verdicts

    # ── The parser both halves share ─────────────────────────────────

    def _analyze(self, exchanges: list[Exchange]) -> dict:
        """Rebuild baseline detection + per-component results off the record."""
        baseline = [e for e in exchanges if BASELINE_PREFIX in self._input_of(e) and not e.error]
        if len(baseline) < 2 or baseline[0].elapsed_ms is None or baseline[1].elapsed_ms is None:
            return {"caching_detected": False, "key_results": []}

        uncached_ms = baseline[0].elapsed_ms
        cached_ms = baseline[1].elapsed_ms
        if (baseline[0].response_status or 0) >= 400:
            return {"caching_detected": False, "key_results": []}

        caching_detected = cached_ms < uncached_ms * 0.7
        if not caching_detected:
            return {"caching_detected": False, "key_results": []}

        threshold = uncached_ms * 0.7
        key_results = []

        for test in KEY_COMPONENT_TESTS:
            variant = self._variant_of(exchanges, test["variant"])
            if variant is None or variant.error or variant.elapsed_ms is None:
                continue
            variant_ms = variant.elapsed_ms
            cache_hit = variant_ms < threshold
            key_results.append(
                {
                    "test_id": test["id"],
                    "description": test["description"],
                    "component_in_key": not cache_hit,
                    "cache_hit_on_variant": cache_hit,
                    "variant_ms": round(variant_ms, 2),
                    "threshold_ms": round(threshold, 2),
                }
            )

        for test in SYSTEM_PROMPT_TESTS:
            variant = self._system_variant(exchanges, test["system_b"])
            if variant is None or variant.error or variant.elapsed_ms is None:
                continue
            variant_ms = variant.elapsed_ms
            cache_hit = variant_ms < threshold
            key_results.append(
                {
                    "test_id": test["id"],
                    "description": test["description"],
                    "component_in_key": not cache_hit,
                    "cache_hit_on_variant": cache_hit,
                    "variant_ms": round(variant_ms, 2),
                    "threshold_ms": round(threshold, 2),
                }
            )

        return {"caching_detected": True, "key_results": key_results}

    @staticmethod
    def _body_of(exchange: Exchange) -> dict:
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return {}
        return body if isinstance(body, dict) else {}

    def _input_of(self, exchange: Exchange) -> str:
        return self._body_of(exchange).get("input", "")

    def _variant_of(self, exchanges: list[Exchange], variant_query: str) -> Exchange | None:
        for exchange in exchanges:
            if self._input_of(exchange) == variant_query:
                return exchange
        return None

    def _system_variant(self, exchanges: list[Exchange], system_b: str) -> Exchange | None:
        for exchange in exchanges:
            if self._body_of(exchange).get("system") == system_b:
                return exchange
        return None

    def _build_evidence(self, test_result: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Test: {test_result['test_id']} ({test_result.get('description', '')})",
            f"Component in key: {test_result.get('component_in_key', 'unknown')}",
            f"Cache hit on variant: {test_result.get('cache_hit_on_variant', 'unknown')}",
            f"Variant timing: {test_result.get('variant_ms', '?')}ms (threshold: {test_result.get('threshold_ms', '?')}ms)",
        ]
        return "\n".join(lines)
