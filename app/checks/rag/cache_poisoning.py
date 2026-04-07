"""
app/checks/rag/cache_poisoning.py - RAG Cache Poisoning Detection

Test if the RAG caches query results. If a poisoned response gets
cached, it affects all subsequent users with the same query.

Detection:
  - Compare repeated identical queries for response consistency
  - Check cache-related headers (Cache-Control, Age, X-Cache, ETag)
  - Timing analysis (cached responses are faster)

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import time
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

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

    timeout_seconds = 90.0
    delay_between_targets = 1.0

    reason = (
        "If RAG caches poisoned responses, the attack affects all subsequent "
        "users submitting the same or similar query — not just the attacker"
    )
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
        "CWE-524 Use of Cache Containing Sensitive Information",
    ]
    techniques = ["cache detection", "response timing analysis", "cache poisoning"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

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
        cache_behavior: dict[str, Any] = {
            "caching_detected": False,
            "cache_headers": {},
            "identical_responses": False,
            "timing_suggests_cache": False,
        }

        try:
            async with AsyncHttpClient(cfg) as client:
                ep = service_endpoints[0]
                url = ep.get("url", service.url)

                for query in TEST_QUERIES:
                    body = {
                        "query": query,
                        "question": query,
                        "input": query,
                    }

                    # First request
                    t1_start = time.monotonic()
                    resp1 = await client.post(
                        url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                    )
                    t1 = time.monotonic() - t1_start

                    if resp1.error or resp1.status_code >= 400:
                        continue

                    # Check cache headers on first response
                    resp1_hdrs = {k.lower(): v for k, v in resp1.headers.items()}
                    for hdr in CACHE_HEADERS:
                        if hdr in resp1_hdrs:
                            cache_behavior["cache_headers"][hdr] = resp1_hdrs[hdr]

                    # Second request (identical, different "session")
                    t2_start = time.monotonic()
                    resp2 = await client.post(
                        url,
                        json=body,
                        headers={
                            "Content-Type": "application/json",
                            "Cache-Control": "no-cache",
                        },
                    )
                    t2 = time.monotonic() - t2_start

                    if resp2.error or resp2.status_code >= 400:
                        continue

                    # Check cache headers on second response
                    resp2_hdrs = {k.lower(): v for k, v in resp2.headers.items()}
                    for hdr in CACHE_HEADERS:
                        if hdr in resp2_hdrs:
                            cache_behavior["cache_headers"][hdr] = resp2_hdrs[hdr]

                    # Compare responses
                    body1 = resp1.body or ""
                    body2 = resp2.body or ""

                    if body1 and body2 and body1 == body2:
                        cache_behavior["identical_responses"] = True

                    # Timing: second request significantly faster suggests cache
                    if t1 > 0.5 and t2 < t1 * 0.5:
                        cache_behavior["timing_suggests_cache"] = True
                        cache_behavior["timing"] = {
                            "first_ms": int(t1 * 1000),
                            "second_ms": int(t2 * 1000),
                        }

                    if cache_behavior["identical_responses"] or cache_behavior["cache_headers"]:
                        cache_behavior["caching_detected"] = True
                        break

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # Generate observations
        if cache_behavior["caching_detected"]:
            # Check if injection was previously detected
            vuln_endpoints = context.get("vulnerable_rag_endpoints", [])
            has_injection = bool(vuln_endpoints)

            if has_injection and cache_behavior["identical_responses"]:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title="RAG cache poisoning: injected response served to subsequent queries",
                        description=(
                            "RAG caches responses and indirect injection was detected on "
                            "this endpoint. Cached poisoned responses affect all users."
                        ),
                        severity="high",
                        evidence=self._build_evidence(cache_behavior),
                        host=service.host,
                        discriminator="cache-poisoned",
                        target=service,
                        raw_data=cache_behavior,
                        references=self.references,
                    )
                )
            elif cache_behavior["identical_responses"]:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title="RAG caching detected: identical responses to repeated queries",
                        description=(
                            f"Identical responses returned for repeated queries. "
                            f"Cache headers: {cache_behavior['cache_headers'] or 'none'}."
                        ),
                        severity="medium",
                        evidence=self._build_evidence(cache_behavior),
                        host=service.host,
                        discriminator="cache-detected",
                        target=service,
                        raw_data=cache_behavior,
                        references=self.references,
                    )
                )
            else:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title="RAG caching detected but responses vary",
                        description="Cache headers present but responses differ — may use session keys.",
                        severity="low",
                        evidence=self._build_evidence(cache_behavior),
                        host=service.host,
                        discriminator="cache-varied",
                        target=service,
                        raw_data=cache_behavior,
                    )
                )
        else:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="No RAG-level caching detected",
                    description="No caching indicators found in RAG responses.",
                    severity="info",
                    evidence="No cache headers or response duplication detected",
                    host=service.host,
                    discriminator="no-cache",
                    target=service,
                )
            )

        result.outputs["rag_cache_behavior"] = cache_behavior
        return result

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
