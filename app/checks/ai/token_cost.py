"""
app/checks/ai/token_cost.py - Token/Cost Exhaustion Probes

Test if expensive operations can be triggered beyond simple rate limiting.
"""

from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.ai_helpers import format_chat_request_with_extra
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation
from app.lib.parsing import safe_json


class TokenCostExhaustionCheck(BaseCheck):
    """Test for missing output token limits and cost exhaustion vectors."""

    name = "token_cost_exhaustion"
    description = "Test if expensive completions can be triggered without token limits"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["token_cost_info"]

    timeout_seconds = 60.0
    sequential = True
    requests_per_second = 1.0

    reason = "On pay-per-token services, missing output caps allow cost exhaustion attacks"
    references = [
        "OWASP LLM Top 10 - LLM04 Model Denial of Service",
    ]
    techniques = ["denial of service", "cost exhaustion", "resource abuse"]

    # Tests: (name, extra_params, prompt, description)
    COST_TESTS = [
        (
            "max_tokens_extreme",
            {"max_tokens": 100000},
            "Say hello.",
            "Extreme max_tokens value accepted",
        ),
        (
            "max_tokens_high",
            {"max_tokens": 10000},
            "Say hello.",
            "High max_tokens value accepted",
        ),
        (
            "verbose_output",
            {"max_tokens": 4096},
            "Write an extremely detailed 5000 word essay about the history of paperclips. "
            "Include every possible detail.",
            "Verbose output request accepted without truncation",
        ),
        (
            "large_system_prompt",
            {},
            "A" * 8000 + " What is 2+2?",
            "Large input accepted (input token cost)",
        ),
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
                tr = await self._test_cost(url, service, api_format)
                result.observations.extend(tr.observations)
                result.outputs.update(tr.outputs)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _test_cost(self, url: str, service: Service, api_format: str) -> CheckResult:
        result = CheckResult(success=True)
        accepted = []
        rejected = []
        usage_data = None

        cfg = HttpConfig(timeout_seconds=30.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for test_name, extra_params, prompt, desc in self.COST_TESTS:
                    await self._rate_limit()

                    body = format_chat_request_with_extra(prompt, api_format, **extra_params)

                    resp = await client.post(
                        url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                    )

                    if resp.error:
                        continue

                    if resp.status_code == 200:
                        resp_body = safe_json(resp.body) or {}

                        # Check for usage data
                        usage = resp_body.get("usage")
                        if usage and isinstance(usage, dict):
                            usage_data = usage

                        accepted.append(
                            {
                                "test": test_name,
                                "description": desc,
                                "usage": usage,
                            }
                        )
                    elif resp.status_code in (400, 413, 422):
                        # Parameter rejected or payload too large
                        rejected.append(test_name)
                    else:
                        rejected.append(test_name)

        except Exception as e:
            result.errors.append(f"{url}: {e}")
            return result

        host = service.host
        cost_info = {
            "accepted": [a["test"] for a in accepted],
            "rejected": rejected,
            "usage_exposed": usage_data is not None,
        }

        extreme_accepted = any(
            a["test"] in ("max_tokens_extreme", "max_tokens_high") for a in accepted
        )

        if extreme_accepted:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="No output token limit enforced",
                    description="Endpoint accepted extreme max_tokens values — cost exhaustion possible",
                    severity="high",
                    evidence=f"Accepted: {', '.join(a['test'] for a in accepted)}",
                    host=host,
                    discriminator="no-token-limit",
                    target=service,
                    target_url=url,
                    raw_data={"accepted": accepted, "usage": usage_data},
                    references=self.references,
                )
            )
        elif accepted:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Large completions accepted ({len(accepted)} tests)",
                    description="Some expensive operations are possible",
                    severity="medium",
                    evidence=f"Accepted: {', '.join(a['test'] for a in accepted)}",
                    host=host,
                    discriminator="large-completions",
                    target=service,
                    target_url=url,
                    raw_data={"accepted": accepted},
                )
            )
        else:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="Token limits enforced",
                    description="Cost exhaustion tests were rejected",
                    severity="info",
                    evidence=f"Rejected: {', '.join(rejected)}",
                    host=host,
                    discriminator="token-limits-ok",
                    target=service,
                    target_url=url,
                )
            )

        result.outputs[f"token_cost_{service.port}"] = cost_info
        return result
