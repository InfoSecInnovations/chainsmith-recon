"""
app/checks/cag/provider_caching.py - Provider-Specific Prompt Caching Analysis

Analyze provider-level prompt caching behavior (OpenAI/Anthropic) and
detect information leakage via cached token counts.

Attack vectors:
- Shared system prompt detection via cached_tokens counts
- Cross-user prefix sharing inference
- Provider caching metadata leakage

**Probe/grade.** The probe sends the fixed payload matrix
(three OpenAI-style, two Anthropic-style, two generic) to each endpoint, records
every exchange, and hands them over as one candidate per endpoint — each
observation carries that endpoint's `target_url`, so it cannot be one candidate
per service (§0.15). `grade()` re-reads the recorded bytes; `_reading()` is the
one parser both halves call (§0.12).

`grade()` never sees which payload produced which response (§0.16). It recovers
that by matching each recorded *request body* back to the payload matrix
(`_match`), so `test_index` and `provider_style` are reconstructed from the
record rather than a remembered loop index.

**Fixed**: the discriminator embeds the endpoint path, an
unbounded value, so the contract declares no `observations:` map and `grade()`
places the real severity (the `ai_model_info_check` pattern). Confidence is
where the split pays: a `cached_tokens` field is the *provider's own* usage
self-report — a proxy can fabricate it — and a shared prefix is inferred from
similar cached-token counts, which also occur when unrelated prompts happen to
be the same length.

References:
  https://www.anthropic.com/news/prompt-caching
  https://platform.openai.com/docs/guides/prompt-caching
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

_OPENAI_PAYLOADS = [
    {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is 2+2?"},
        ],
    },
    {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of Spain?"},
        ],
    },
    {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a coding expert."},
            {"role": "user", "content": "What is 2+2?"},
        ],
    },
]

_ANTHROPIC_PAYLOADS = [
    {
        "model": "claude-3-sonnet-20240229",
        "messages": [{"role": "user", "content": "What is 2+2?"}],
        "system": "You are a helpful assistant.",
    },
    {
        "model": "claude-3-sonnet-20240229",
        "messages": [{"role": "user", "content": "What is the capital of Spain?"}],
        "system": "You are a helpful assistant.",
    },
]

_GENERIC_PAYLOADS = [
    {"input": "What is 2+2?", "query": "What is 2+2?"},
    {"input": "What is the capital of Spain?", "query": "capital"},
]

# The full matrix in send order, each paired with the provider style the
# original assigned it. `test_index` is the position in this list.
ALL_PAYLOADS: list[tuple[dict, str]] = (
    [(p, "openai") for p in _OPENAI_PAYLOADS]
    + [(p, "anthropic") for p in _ANTHROPIC_PAYLOADS]
    + [(p, "generic") for p in _GENERIC_PAYLOADS]
)


class ProviderCachingCheck(ServiceIteratingCheck):
    """
    Analyze provider-level prompt caching behavior and token leakage.

    Sends requests and examines usage metadata (cached_tokens) to detect
    shared system prompt prefixes and cross-user caching behavior.
    """

    name = "cag_provider_caching"
    description = "Analyze provider-level prompt caching behavior and token leakage"
    intrusive = False

    conditions = [CheckCondition("cag_endpoints", "truthy")]
    produces = ["provider_cache_info"]
    service_types = ["ai", "api", "http"]

    reason = "Provider-level prompt caching may reveal shared system prompts and cross-user prefix sharing"
    references = [
        "https://www.anthropic.com/news/prompt-caching",
        "https://platform.openai.com/docs/guides/prompt-caching",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["token analysis", "prompt caching detection", "usage metadata inspection"]

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
        provider_results = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for endpoint in service_endpoints:
                    url = endpoint.get("url", service.url)
                    path = endpoint.get("path", "unknown").strip("/").replace("/", "-")
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"provider-cache-{path}",
                        target=service,
                        target_url=url,
                    )

                    for payload, _style in ALL_PAYLOADS:
                        resp = await client.post(url, json=payload, headers=JSON_HEADERS)
                        candidate.attach(
                            exchange_from_response(
                                resp,
                                check_name=self.name,
                                scan_id=scan_id,
                                host=service.host,
                                method="POST",
                                request_headers=JSON_HEADERS,
                                request_json=payload,
                            )
                        )

                    reading = self._reading(candidate.exchanges, url)
                    if reading:
                        provider_results.append(reading)
                        result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if provider_results:
            result.outputs["provider_cache_info"] = provider_results

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        reading = self._reading(list(evidence), ctx.target_url or "")
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
                    "caching_detected": reading["caching_detected"],
                    "shared_prefix_detected": reading["shared_prefix_detected"],
                    "tests_run": reading["tests_run"],
                },
                references=self.references,
                raw_data=reading,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    @staticmethod
    def _confidence(reading: dict) -> tuple[float, str]:
        if reading.get("shared_prefix_detected"):
            return 0.5, (
                "inferred from several queries reporting near-identical `cached_tokens` "
                "counts, but the same counts arise whenever unrelated prompts happen to share "
                "a length, and the usage block is the provider's own self-report"
            )
        if reading.get("caching_detected"):
            return 0.6, (
                "a non-zero `cached_tokens` appears in the usage metadata, which is the "
                "provider's self-report — a gateway or proxy can populate that field without "
                "any real cross-request cache"
            )
        return 0.5, (
            "no usage metadata reported a cache; a provider that caches silently, or reports "
            "it under a field name not in the checked set, would look identical"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange], url: str) -> dict | None:
        """Rebuild the provider-caching analysis off the recorded exchanges."""
        url_exchanges = [
            e for e in exchanges if e.request_url == url and e.request_method == "POST"
        ]

        results = []
        for index, (payload, style) in enumerate(ALL_PAYLOADS):
            exchange = self._match(url_exchanges, payload)
            if exchange is None:
                continue
            token_info = self._token_info(exchange)
            if token_info is None:
                continue
            token_info["test_index"] = index
            token_info["provider_style"] = style
            results.append(token_info)

        if not results:
            return None

        has_cached_tokens = any(r.get("cached_tokens", 0) > 0 for r in results)
        shared_prefix = self._detect_shared_prefix(results)

        return {
            "url": url,
            "tests_run": len(results),
            "caching_detected": has_cached_tokens,
            "shared_prefix_detected": shared_prefix,
            "results": results,
        }

    @staticmethod
    def _match(exchanges: list[Exchange], payload: dict) -> Exchange | None:
        """The exchange whose recorded request body is this payload."""
        for exchange in exchanges:
            try:
                body = json.loads(exchange.request_body or "{}")
            except (json.JSONDecodeError, TypeError):
                continue
            if body == payload:
                return exchange
        return None

    @staticmethod
    def _token_info(exchange: Exchange) -> dict | None:
        """Extract cached-token information off one recorded response."""
        if exchange.error or (exchange.response_status or 0) >= 400:
            return None
        try:
            data = json.loads(exchange.response_body or "")
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(data, dict):
            return None

        usage = data.get("usage", {})
        if not isinstance(usage, dict):
            return None

        cached_tokens = (
            usage.get("cached_tokens")
            or usage.get("prompt_tokens_cached")
            or usage.get("cache_read_input_tokens")
            or 0
        )
        total_tokens = (
            usage.get("prompt_tokens")
            or usage.get("input_tokens")
            or usage.get("total_tokens")
            or 0
        )

        if cached_tokens == 0 and total_tokens == 0:
            if "cached" not in data and "cache_hit" not in data:
                return None

        return {
            "cached_tokens": cached_tokens,
            "total_tokens": total_tokens,
            "cache_ratio": (round(cached_tokens / total_tokens, 2) if total_tokens > 0 else 0),
            "provider_style": "openai",
            "raw_usage": usage,
        }

    def _detect_shared_prefix(self, results: list[dict]) -> bool:
        """Detect if cached tokens suggest shared system prompt prefix."""
        cached_counts = [
            r.get("cached_tokens", 0) for r in results if r.get("cached_tokens", 0) > 0
        ]
        if len(cached_counts) < 2:
            return False

        if max(cached_counts) > 0 and min(cached_counts) > 0:
            ratio = min(cached_counts) / max(cached_counts)
            return ratio > 0.8

        return False

    def _determine_severity(self, cache_info: dict) -> str:
        """Determine observation severity."""
        if cache_info.get("shared_prefix_detected"):
            return "medium"
        if cache_info.get("caching_detected"):
            return "low"
        return "info"

    def _build_title(self, cache_info: dict) -> str:
        """Build observation title."""
        if cache_info.get("shared_prefix_detected"):
            return "Provider caching reveals shared system prompt across queries"
        if cache_info.get("caching_detected"):
            return "Provider prompt caching active"
        return "No provider-level prompt caching detected"

    def _build_description(self, cache_info: dict) -> str:
        """Build observation description."""
        if cache_info.get("shared_prefix_detected"):
            cached_counts = [
                r.get("cached_tokens", 0)
                for r in cache_info.get("results", [])
                if r.get("cached_tokens", 0) > 0
            ]
            avg_cached = sum(cached_counts) / len(cached_counts) if cached_counts else 0
            return (
                f"Provider-level prompt caching detected with an average of "
                f"{int(avg_cached)} cached tokens across different queries. "
                f"This suggests a shared system prompt prefix is being cached "
                f"across users, revealing prompt structure information."
            )
        if cache_info.get("caching_detected"):
            return (
                "Provider-level prompt caching is active. Cached token counts "
                "are reported in usage metadata."
            )
        return "No provider-level prompt caching behavior detected."

    def _build_evidence(self, cache_info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Tests run: {cache_info['tests_run']}",
            f"Caching detected: {cache_info['caching_detected']}",
            f"Shared prefix: {cache_info['shared_prefix_detected']}",
        ]

        for r in cache_info.get("results", [])[:5]:
            if r.get("cached_tokens", 0) > 0:
                lines.append(
                    f"  Test {r.get('test_index', '?')}: "
                    f"{r['cached_tokens']}/{r.get('total_tokens', '?')} tokens cached "
                    f"({r.get('cache_ratio', 0):.0%})"
                )

        return "\n".join(lines)
