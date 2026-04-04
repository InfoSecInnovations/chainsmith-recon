"""
app/checks/cag/provider_caching.py - Provider-Specific Prompt Caching Analysis

Analyze provider-level prompt caching behavior (OpenAI/Anthropic) and
detect information leakage via cached token counts.

Attack vectors:
- Shared system prompt detection via cached_tokens counts
- Cross-user prefix sharing inference
- Provider caching metadata leakage

References:
  https://www.anthropic.com/news/prompt-caching
  https://platform.openai.com/docs/guides/prompt-caching
  OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure
"""

import json
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig


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

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = "Provider-level prompt caching may reveal shared system prompts and cross-user prefix sharing"
    references = [
        "https://www.anthropic.com/news/prompt-caching",
        "https://platform.openai.com/docs/guides/prompt-caching",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["token analysis", "prompt caching detection", "usage metadata inspection"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

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
                    cache_info = await self._analyze_provider_caching(client, url, service)

                    if cache_info:
                        provider_results.append(cache_info)

                        severity = self._determine_severity(cache_info)
                        result.findings.append(
                            build_finding(
                                check_name=self.name,
                                title=self._build_title(cache_info),
                                description=self._build_description(cache_info),
                                severity=severity,
                                evidence=self._build_evidence(cache_info),
                                host=service.host,
                                discriminator=f"provider-cache-{endpoint.get('path', 'unknown').strip('/').replace('/', '-')}",
                                target=service,
                                target_url=url,
                                raw_data=cache_info,
                                references=self.references,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if provider_results:
            result.outputs["provider_cache_info"] = provider_results

        return result

    async def _analyze_provider_caching(
        self, client: AsyncHttpClient, url: str, service: Service
    ) -> dict | None:
        """Analyze provider caching via usage metadata."""
        cached_tokens_results = []

        # Test 1: OpenAI-style request with system message
        openai_payloads = [
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

        for i, payload in enumerate(openai_payloads):
            token_info = await self._send_and_check_tokens(client, url, payload)
            if token_info:
                token_info["test_index"] = i
                cached_tokens_results.append(token_info)

        # Test 2: Anthropic-style request
        anthropic_payloads = [
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

        for i, payload in enumerate(anthropic_payloads):
            token_info = await self._send_and_check_tokens(client, url, payload)
            if token_info:
                token_info["test_index"] = len(openai_payloads) + i
                token_info["provider_style"] = "anthropic"
                cached_tokens_results.append(token_info)

        # Also try generic endpoints
        generic_payloads = [
            {"input": "What is 2+2?", "query": "What is 2+2?"},
            {"input": "What is the capital of Spain?", "query": "capital"},
        ]

        for i, payload in enumerate(generic_payloads):
            token_info = await self._send_and_check_tokens(client, url, payload)
            if token_info:
                token_info["test_index"] = len(openai_payloads) + len(anthropic_payloads) + i
                token_info["provider_style"] = "generic"
                cached_tokens_results.append(token_info)

        if not cached_tokens_results:
            return None

        # Analyze results
        has_cached_tokens = any(r.get("cached_tokens", 0) > 0 for r in cached_tokens_results)
        shared_prefix = self._detect_shared_prefix(cached_tokens_results)

        return {
            "url": url,
            "tests_run": len(cached_tokens_results),
            "caching_detected": has_cached_tokens,
            "shared_prefix_detected": shared_prefix,
            "results": cached_tokens_results,
        }

    async def _send_and_check_tokens(
        self, client: AsyncHttpClient, url: str, payload: dict
    ) -> dict | None:
        """Send a request and extract cached token information."""
        try:
            resp = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )

            if resp.error or resp.status_code >= 400:
                return None

            try:
                data = json.loads(resp.body)
            except (json.JSONDecodeError, TypeError):
                return None

            if not isinstance(data, dict):
                return None

            # Extract usage metadata
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
                # Check for cache fields outside usage
                if "cached" not in data and "cache_hit" not in data:
                    return None

            return {
                "cached_tokens": cached_tokens,
                "total_tokens": total_tokens,
                "cache_ratio": (round(cached_tokens / total_tokens, 2) if total_tokens > 0 else 0),
                "provider_style": "openai",
                "raw_usage": usage,
            }

        except Exception:
            return None

    def _detect_shared_prefix(self, results: list[dict]) -> bool:
        """Detect if cached tokens suggest shared system prompt prefix."""
        cached_counts = [
            r.get("cached_tokens", 0) for r in results if r.get("cached_tokens", 0) > 0
        ]
        if len(cached_counts) < 2:
            return False

        # If multiple different queries have similar cached token counts,
        # they likely share a system prompt prefix
        if max(cached_counts) > 0 and min(cached_counts) > 0:
            ratio = min(cached_counts) / max(cached_counts)
            return ratio > 0.8

        return False

    def _determine_severity(self, cache_info: dict) -> str:
        """Determine finding severity."""
        if cache_info.get("shared_prefix_detected"):
            return "medium"
        if cache_info.get("caching_detected"):
            return "low"
        return "info"

    def _build_title(self, cache_info: dict) -> str:
        """Build finding title."""
        if cache_info.get("shared_prefix_detected"):
            return "Provider caching reveals shared system prompt across queries"
        if cache_info.get("caching_detected"):
            return "Provider prompt caching active"
        return "No provider-level prompt caching detected"

    def _build_description(self, cache_info: dict) -> str:
        """Build finding description."""
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
