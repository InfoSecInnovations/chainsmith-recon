"""
app/checks/ai/cache_detect.py - Response Caching Detection

Send identical requests and compare responses. If responses are identical
(content and timing), the service may be caching.
"""

from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.ai_helpers import extract_response_text, format_chat_request_with_extra
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import safe_json


class ResponseCachingCheck(BaseCheck):
    """Detect response caching by comparing identical requests."""

    name = "response_caching"
    description = (
        "Detect response caching by comparing identical requests for content and timing patterns"
    )
    intrusive = False

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["cache_detection_results"]

    timeout_seconds = 60.0
    sequential = True
    requests_per_second = 2.0

    reason = "Cached responses may bypass content filters that operate on generation time"
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
    ]
    techniques = ["caching detection", "response analysis"]

    TEST_PROMPT = "What is the capital of France? Answer in one sentence."
    REPEAT_COUNT = 3

    # Cache-related headers to look for
    CACHE_HEADERS = [
        "x-cache",
        "x-cache-hit",
        "age",
        "cache-control",
        "cf-cache-status",
        "x-varnish",
        "x-proxy-cache",
        "x-fastly-request-id",
    ]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        for endpoint_info in context.get("chat_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))
            api_format = endpoint_info.get("api_format", "unknown")

            try:
                cr = await self._test_caching(url, service, api_format)
                result.findings.extend(cr.findings)
                result.outputs.update(cr.outputs)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _test_caching(
        self,
        url: str,
        service: Service,
        api_format: str,
    ) -> CheckResult:
        result = CheckResult(success=True)
        host = service.host

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        responses_text = []
        response_times = []
        cache_headers_found = {}
        temp_override_works = False

        try:
            async with AsyncHttpClient(cfg) as client:
                # Send identical requests
                for _ in range(self.REPEAT_COUNT):
                    await self._rate_limit()

                    body = format_chat_request_with_extra(
                        self.TEST_PROMPT,
                        api_format,
                        temperature=0,
                    )
                    resp = await client.post(
                        url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                    )

                    if resp.error or resp.status_code != 200:
                        continue

                    parsed = safe_json(resp.body) or {}
                    text = extract_response_text(parsed, api_format)
                    responses_text.append(text)
                    response_times.append(resp.elapsed_ms)

                    # Check cache headers
                    for header in self.CACHE_HEADERS:
                        val = resp.headers.get(header)
                        if val:
                            cache_headers_found[header] = val

                # Temperature override test: if responses at temp=0 are identical,
                # check if temp=2.0 produces different responses
                if len(responses_text) >= 2 and len(set(responses_text)) == 1:
                    await self._rate_limit()
                    body_hot = format_chat_request_with_extra(
                        self.TEST_PROMPT,
                        api_format,
                        temperature=2.0,
                    )
                    resp_hot = await client.post(
                        url,
                        json=body_hot,
                        headers={"Content-Type": "application/json"},
                    )

                    if resp_hot.status_code == 200 and not resp_hot.error:
                        parsed_hot = safe_json(resp_hot.body) or {}
                        text_hot = extract_response_text(parsed_hot, api_format)
                        # If same response despite different temperature, likely cached
                        if text_hot == responses_text[0]:
                            temp_override_works = False  # Cache overrides temperature
                        else:
                            temp_override_works = True  # Temperature works, not cached

        except Exception as e:
            result.errors.append(f"{url}: {e}")
            return result

        if len(responses_text) < 2:
            return result

        cache_info = {
            "identical_responses": len(set(responses_text)) == 1,
            "cache_headers": cache_headers_found,
            "avg_response_ms": sum(response_times) / len(response_times)
            if response_times
            else None,
            "temp_override_works": temp_override_works,
        }

        # Detect caching
        all_identical = len(set(responses_text)) == 1

        if cache_headers_found:
            header_str = ", ".join(f"{k}: {v}" for k, v in cache_headers_found.items())
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Cache headers present: {header_str[:80]}",
                    description="Response includes cache-related headers indicating proxy/CDN caching",
                    severity="low",
                    evidence=f"Headers: {header_str}",
                    host=host,
                    discriminator="cache-headers",
                    target=service,
                    target_url=url,
                    raw_data=cache_info,
                )
            )

        if all_identical and not temp_override_works:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="Response caching detected: identical responses override temperature parameter",
                    description=(
                        "Identical responses returned for same prompt regardless of temperature, "
                        "suggesting HTTP-level or semantic caching. "
                        "Content filter bypass risk if cached responses predate filter updates."
                    ),
                    severity="medium",
                    evidence=(
                        f"Responses: {self.REPEAT_COUNT}/{self.REPEAT_COUNT} identical, "
                        f"temperature=2.0 produced same output"
                    ),
                    host=host,
                    discriminator="caching-detected",
                    target=service,
                    target_url=url,
                    raw_data=cache_info,
                    references=self.references,
                )
            )
        elif all_identical:
            # Identical at temp=0 but different at temp=2.0 — deterministic, not cached
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="No caching detected (deterministic at temperature=0, varies at temperature=2.0)",
                    description="Responses are deterministic at low temperature but vary with high temperature, as expected",
                    severity="info",
                    evidence=f"Responses: {self.REPEAT_COUNT}/{self.REPEAT_COUNT} identical at temp=0, different at temp=2.0",
                    host=host,
                    discriminator="no-cache",
                    target=service,
                    target_url=url,
                )
            )
        else:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="No caching detected (responses vary as expected)",
                    description="Responses vary across identical requests, indicating no caching",
                    severity="info",
                    evidence=f"Unique responses: {len(set(responses_text))}/{len(responses_text)}",
                    host=host,
                    discriminator="no-cache",
                    target=service,
                    target_url=url,
                )
            )

        result.outputs[f"cache_detection_{service.port}"] = cache_info
        return result
