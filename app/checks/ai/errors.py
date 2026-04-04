"""
app/checks/ai/errors.py - AI Error Leakage Check

Test for information disclosure in AI error responses.
"""

import re
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.evidence import fmt_error_evidence
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig


class AIErrorLeakageCheck(BaseCheck):
    """Check for information leakage in AI error responses."""

    name = "ai_error_leakage"
    description = "Test for sensitive information disclosure in AI error responses"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["error_leaks"]

    timeout_seconds = 60.0
    sequential = True
    delay_between_targets = 0.5

    reason = "Error messages often reveal internal paths, tool names, and configuration details"
    references = ["OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure", "CWE-209"]
    techniques = ["error triggering", "information gathering", "debug mode detection"]

    ERROR_PAYLOADS = [
        {},
        {"message": None},
        {"messages": "not_an_array"},
        {"messages": [{"role": "invalid"}]},
        {"model": "nonexistent-model-xyz"},
        {"max_tokens": -1},
        {"temperature": 999},
    ]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        for endpoint_info in context.get("chat_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))
            try:
                ep_result = await self._test_errors(url, service)
                result.findings.extend(ep_result.findings)
                result.outputs.update(ep_result.outputs)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _test_errors(self, url: str, service: Service) -> CheckResult:
        result = CheckResult(success=True)
        leaked = {"paths": [], "tools": [], "stack_traces": False, "config": []}

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for payload in self.ERROR_PAYLOADS:
                    await self._rate_limit()
                    resp = await client.post(
                        url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )

                    if resp.error or resp.status_code < 400:
                        continue

                    body = resp.body.lower()

                    if any(
                        ind in body
                        for ind in ["traceback", "at line", 'file "', "exception in", "error at"]
                    ):
                        leaked["stack_traces"] = True

                    leaked["paths"].extend(re.findall(r"/[a-zA-Z0-9_/.-]+\.py", body))

                    if any(kw in body for kw in ["tools", "available_tools", "function"]):
                        leaked["tools"].extend(
                            [t for t in re.findall(r'["\']([a-z_]+)["\']', body) if "_" in t]
                        )

                    for pattern in [
                        "model",
                        "temperature",
                        "max_tokens",
                        "api_key",
                        "endpoint",
                        "base_url",
                    ]:
                        if pattern in body:
                            leaked["config"].append(pattern)

        except Exception as e:
            result.errors.append(f"{url}: {e}")
            return result

        leaked["paths"] = list(set(leaked["paths"]))
        leaked["tools"] = list(set(leaked["tools"]))
        leaked["config"] = list(set(leaked["config"]))

        host = service.host

        if leaked["stack_traces"]:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="Stack trace in error response",
                    description="Error responses contain stack traces revealing internal code paths",
                    severity="medium",
                    evidence="Stack trace indicators found in error responses",
                    host=host,
                    discriminator="stack-trace",
                    target=service,
                    target_url=url,
                    references=["CWE-209"],
                )
            )

        if leaked["paths"]:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Internal paths leaked ({len(leaked['paths'])})",
                    description="Error messages reveal internal file paths",
                    severity="low",
                    evidence=fmt_error_evidence(url, ", ".join(leaked["paths"][:5])),
                    host=host,
                    discriminator="internal-paths",
                    target=service,
                    target_url=url,
                )
            )

        if leaked["tools"]:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Tools leaked in errors ({len(leaked['tools'])})",
                    description="Error messages reveal available tool/function names",
                    severity="medium",
                    evidence=f"Tools: {', '.join(leaked['tools'][:5])}",
                    host=host,
                    discriminator="tools-leaked",
                    target=service,
                    target_url=url,
                    raw_data={"tools": leaked["tools"]},
                )
            )

        if leaked["config"]:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="Configuration leaked in errors",
                    description="Error messages reveal configuration parameters",
                    severity="low",
                    evidence=f"Config hints: {', '.join(leaked['config'])}",
                    host=host,
                    discriminator="config-leaked",
                    target=service,
                    target_url=url,
                )
            )

        result.outputs["error_leaks"] = leaked
        return result
