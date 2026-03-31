"""
app/checks/ai/rate_limits.py - Rate Limit Detection

Map rate limiting behavior and identify bypass opportunities.
"""

import asyncio
from typing import Any

from app.checks.base import BaseCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding
from app.lib.ai_helpers import format_chat_request, fmt_rate_limit_evidence
from app.lib.parsing import extract_headers_dict


class RateLimitCheck(BaseCheck):
    """Detect and map rate limiting behavior."""

    name = "rate_limit_check"
    description = "Detect rate limiting thresholds and bypass opportunities"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["rate_limit_info"]

    timeout_seconds = 45.0
    sequential = True

    reason = "Understanding rate limits helps plan attacks and identify DoS vectors"
    references = ["OWASP API4:2023 - Unrestricted Resource Consumption"]
    techniques = ["rate limit testing", "resource exhaustion", "bypass techniques"]

    TEST_REQUESTS = 12
    REQUEST_DELAY = 0.08

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        for endpoint_info in context.get("chat_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))
            api_format = endpoint_info.get("api_format", "unknown")

            try:
                rr = await self._test_rate_limits(url, service, api_format)
                result.findings.extend(rr.findings)
                result.outputs.update(rr.outputs)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _test_rate_limits(self, url: str, service: Service, api_format: str) -> CheckResult:
        result = CheckResult(success=True)
        rate_info = {"detected": False, "threshold": None, "headers": {}}

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for i in range(self.TEST_REQUESTS):
                    resp = await client.post(
                        url,
                        json=format_chat_request("Hi", api_format, max_tokens=5),
                        headers={"Content-Type": "application/json"},
                    )

                    if resp.error:
                        await asyncio.sleep(self.REQUEST_DELAY)
                        continue

                    headers_lower = extract_headers_dict(resp.headers)
                    for h in ("x-ratelimit-limit", "x-ratelimit-remaining", "retry-after"):
                        if h in headers_lower:
                            rate_info["headers"][h] = headers_lower[h]

                    if resp.status_code == 429:
                        rate_info["detected"] = True
                        rate_info["threshold"] = i
                        break

                    await asyncio.sleep(self.REQUEST_DELAY)

        except Exception as e:
            result.errors.append(f"{url}: {e}")
            return result

        host = service.host

        if rate_info["detected"]:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Rate limiting detected (threshold: ~{rate_info['threshold']} requests)",
                description="Endpoint enforces rate limiting",
                severity="info",
                evidence=fmt_rate_limit_evidence(rate_info["threshold"], 429, rate_info["headers"]),
                host=host, discriminator="rate-limit-detected",
                target=service, target_url=url,
            ))
        elif rate_info["headers"]:
            result.findings.append(build_finding(
                check_name=self.name,
                title="Rate limit headers present",
                description="Rate limiting configured but threshold not reached in testing",
                severity="info",
                evidence=fmt_rate_limit_evidence(self.TEST_REQUESTS, 200, rate_info["headers"]),
                host=host, discriminator="rate-limit-headers",
                target=service, target_url=url,
            ))
        else:
            result.findings.append(build_finding(
                check_name=self.name,
                title="No rate limiting detected",
                description=f"No rate limiting after {self.TEST_REQUESTS} requests — potential DoS vector",
                severity="medium",
                evidence=fmt_rate_limit_evidence(self.TEST_REQUESTS, 200, {}),
                host=host, discriminator="no-rate-limit",
                target=service, target_url=url,
                references=["OWASP API4:2023"],
            ))

        result.outputs[f"rate_limit_{service.port}"] = rate_info
        return result
