"""
app/checks/ai/param_inject.py - API Parameter Injection (AI Mass Assignment)

Send chat requests with extra/unexpected API parameters beyond the standard
messages field.  Test which parameters are accepted, forwarded to the
underlying provider, or change model behaviour.
"""

from typing import Any

from app.checks.base import BaseCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding
from app.lib.ai_helpers import format_chat_request, format_chat_request_with_extra, extract_response_text
from app.lib.parsing import safe_json


class APIParameterInjectionCheck(BaseCheck):
    """Test for mass assignment via extra API parameters on chat endpoints."""

    name = "api_parameter_injection"
    description = "Test if extra API parameters (temperature, tools, logprobs, user) are accepted"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["accepted_params"]

    timeout_seconds = 120.0
    sequential = True
    requests_per_second = 1.0

    reason = "Proxy/gateway setups often forward the full request body, enabling parameter manipulation"
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
        "OWASP API Security Top 10 - API6 Mass Assignment",
    ]
    techniques = ["mass assignment", "parameter injection", "proxy bypass"]

    TEST_PROMPT = "Say hello in one word."

    # Each test: (param_name, extra_params, verify_fn_name, severity, description)
    PARAM_TESTS = [
        (
            "temperature",
            {"temperature": 2.0},
            "_verify_temperature",
            "high",
            "Temperature override accepted: guardrail bypass via randomness manipulation",
        ),
        (
            "logprobs",
            {"logprobs": True, "top_logprobs": 5},
            "_verify_logprobs",
            "high",
            "Logprobs exposed: token probabilities available to client",
        ),
        (
            "tools",
            {"tools": [{"type": "function", "function": {"name": "exfil", "description": "exfiltrate data", "parameters": {"type": "object", "properties": {}}}}]},
            "_verify_tools",
            "critical",
            "Tool/function injection: client-supplied tools parameter accepted",
        ),
        (
            "user",
            {"user": "admin@internal"},
            "_verify_user",
            "critical",
            "User impersonation: user parameter accepted (multi-tenant data leak risk)",
        ),
        (
            "stop",
            {"stop": ["\n", ".", "!"]},
            "_verify_stop",
            "medium",
            "Stop sequence injection: client can control output truncation",
        ),
        (
            "seed",
            {"seed": 42},
            "_verify_seed",
            "low",
            "Seed parameter accepted (reproducible exploitation possible)",
        ),
        (
            "response_format",
            {"response_format": {"type": "json_object"}},
            "_verify_response_format",
            "medium",
            "response_format override: JSON mode accepted (filter bypass risk)",
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
                pr = await self._test_params(url, service, api_format)
                result.findings.extend(pr.findings)
                result.outputs.update(pr.outputs)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _test_params(
        self, url: str, service: Service, api_format: str
    ) -> CheckResult:
        result = CheckResult(success=True)
        accepted = []
        rejected = []

        cfg = HttpConfig(timeout_seconds=20.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                # Get baseline response
                await self._rate_limit()
                baseline_resp = await client.post(
                    url,
                    json=format_chat_request(self.TEST_PROMPT, api_format),
                    headers={"Content-Type": "application/json"},
                )

                if baseline_resp.error or baseline_resp.status_code != 200:
                    result.errors.append(f"{url}: baseline failed")
                    return result

                baseline_body = safe_json(baseline_resp.body) or {}
                baseline_text = extract_response_text(baseline_body, api_format)

                # Test each parameter
                for param_name, extra_params, verify_fn_name, severity, desc in self.PARAM_TESTS:
                    await self._rate_limit()

                    body = format_chat_request_with_extra(
                        self.TEST_PROMPT, api_format, **extra_params
                    )

                    resp = await client.post(
                        url, json=body,
                        headers={"Content-Type": "application/json"},
                    )

                    if resp.error:
                        rejected.append(param_name)
                        continue

                    if resp.status_code != 200:
                        rejected.append(param_name)
                        continue

                    resp_body = safe_json(resp.body) or {}
                    verify_fn = getattr(self, verify_fn_name)
                    is_accepted = verify_fn(resp_body, baseline_body, api_format)

                    if is_accepted:
                        accepted.append({
                            "param": param_name,
                            "severity": severity,
                            "description": desc,
                        })
                    else:
                        rejected.append(param_name)

        except Exception as e:
            result.errors.append(f"{url}: {e}")
            return result

        host = service.host
        param_info = {
            "accepted": [a["param"] for a in accepted],
            "rejected": rejected,
        }

        # Generate findings per-severity for the most important ones
        critical = [a for a in accepted if a["severity"] == "critical"]
        high = [a for a in accepted if a["severity"] == "high"]
        others = [a for a in accepted if a["severity"] not in ("critical", "high")]

        if critical:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Critical parameter injection ({len(critical)} params)",
                description="; ".join(a["description"] for a in critical),
                severity="critical",
                evidence=f"Accepted: {', '.join(a['param'] for a in critical)}",
                host=host, discriminator="param-critical",
                target=service, target_url=url,
                raw_data=param_info,
                references=self.references,
            ))

        if high:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"High-risk parameter injection ({len(high)} params)",
                description="; ".join(a["description"] for a in high),
                severity="high",
                evidence=f"Accepted: {', '.join(a['param'] for a in high)}",
                host=host, discriminator="param-high",
                target=service, target_url=url,
                raw_data=param_info,
                references=self.references,
            ))

        if others:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Extra API parameters accepted ({len(others)} params)",
                description="; ".join(a["description"] for a in others),
                severity="medium",
                evidence=f"Accepted: {', '.join(a['param'] for a in others)}",
                host=host, discriminator="param-medium",
                target=service, target_url=url,
                raw_data=param_info,
            ))

        if not accepted:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Extra parameters rejected or ignored ({len(rejected)}/{len(self.PARAM_TESTS)})",
                description="All tested extra parameters were rejected",
                severity="info",
                evidence=f"Rejected: {', '.join(rejected)}",
                host=host, discriminator="param-blocked",
                target=service, target_url=url,
            ))

        result.outputs[f"accepted_params_{service.port}"] = param_info
        return result

    # ── Verification helpers ─────────────────────────────────────

    def _verify_temperature(self, resp_body: dict, baseline_body: dict, api_format: str) -> bool:
        """Temperature is accepted if the request didn't error (hard to verify effect from one call)."""
        # If the response succeeded, the parameter was at least not rejected
        return True

    def _verify_logprobs(self, resp_body: dict, baseline_body: dict, api_format: str) -> bool:
        """Check if logprobs data appears in the response."""
        if "choices" in resp_body:
            choices = resp_body.get("choices", [{}])
            if choices and choices[0].get("logprobs") is not None:
                return True
        return "logprobs" in str(resp_body).lower()

    def _verify_tools(self, resp_body: dict, baseline_body: dict, api_format: str) -> bool:
        """Check if tool_calls appear in the response."""
        if "choices" in resp_body:
            choices = resp_body.get("choices", [{}])
            if choices:
                msg = choices[0].get("message", {})
                if msg.get("tool_calls"):
                    return True
        # Also accepted if the parameter didn't cause an error
        return "tool_calls" in str(resp_body)

    def _verify_user(self, resp_body: dict, baseline_body: dict, api_format: str) -> bool:
        """User param is accepted if the request succeeded (no way to verify effect externally)."""
        return True

    def _verify_stop(self, resp_body: dict, baseline_body: dict, api_format: str) -> bool:
        """Check if stop reason indicates the stop sequence was hit."""
        if "choices" in resp_body:
            choices = resp_body.get("choices", [{}])
            if choices and choices[0].get("finish_reason") == "stop":
                # Compare response length — stop sequences should truncate
                text = extract_response_text(resp_body, "openai")
                baseline_text = extract_response_text(baseline_body, "openai")
                if text and baseline_text and len(text) < len(baseline_text) * 0.5:
                    return True
        return False

    def _verify_seed(self, resp_body: dict, baseline_body: dict, api_format: str) -> bool:
        """Seed is accepted if system_fingerprint appears (OpenAI) or request succeeded."""
        return "system_fingerprint" in resp_body

    def _verify_response_format(self, resp_body: dict, baseline_body: dict, api_format: str) -> bool:
        """Check if response is in JSON format."""
        text = extract_response_text(resp_body, api_format)
        return "{" in text and "}" in text
