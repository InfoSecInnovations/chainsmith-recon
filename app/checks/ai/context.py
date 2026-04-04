"""
app/checks/ai/context.py - Context Window Probing

Estimate context window limits and token handling behavior.
"""

from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.ai_helpers import fmt_context_evidence, format_chat_request
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import safe_json


class ContextWindowCheck(BaseCheck):
    """Probe context window limits."""

    name = "context_window_check"
    description = "Estimate context window size and token limits"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["context_info"]

    timeout_seconds = 60.0
    sequential = True
    requests_per_second = 0.5

    reason = "Context limits affect prompt injection payload sizes and conversation hijacking"
    references = ["OWASP LLM Top 10"]
    techniques = ["context probing", "token estimation"]

    TEST_SIZES = [
        (100, "A" * 400),
        (500, "word " * 500),
        (2000, "test " * 2000),
        (4000, "data " * 4000),
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
                cr = await self._probe_context(url, service, api_format)
                result.findings.extend(cr.findings)
                result.outputs.update(cr.outputs)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _probe_context(self, url: str, service: Service, api_format: str) -> CheckResult:
        result = CheckResult(success=True)
        ctx_info = {"max_successful": 0, "failed_at": None, "error_type": None}

        cfg = HttpConfig(timeout_seconds=30.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for token_estimate, payload in self.TEST_SIZES:
                    await self._rate_limit()

                    resp = await client.post(
                        url,
                        json=format_chat_request(f"Summarize: {payload}", api_format),
                        headers={"Content-Type": "application/json"},
                    )

                    if resp.error:
                        ctx_info["failed_at"] = token_estimate
                        ctx_info["error_type"] = "connection_error"
                        break

                    if resp.status_code == 200:
                        ctx_info["max_successful"] = token_estimate
                    else:
                        ctx_info["failed_at"] = token_estimate
                        body = safe_json(resp.body) or {}
                        body_str = str(body).lower()
                        if "context" in body_str or "token" in body_str:
                            ctx_info["error_type"] = "context_limit"
                        else:
                            ctx_info["error_type"] = "other"
                        break

        except Exception as e:
            result.errors.append(f"{url}: {e}")
            return result

        if ctx_info["max_successful"] > 0:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Context window: ~{ctx_info['max_successful']}+ tokens",
                    description=(
                        f"Successfully processed ~{ctx_info['max_successful']} tokens"
                        + (f", failed at ~{ctx_info['failed_at']}" if ctx_info["failed_at"] else "")
                    ),
                    severity="info",
                    evidence=fmt_context_evidence(
                        ctx_info["max_successful"],
                        ctx_info["failed_at"],
                        ctx_info["error_type"],
                    ),
                    host=service.host,
                    discriminator="context-window",
                    target=service,
                    target_url=url,
                )
            )

        result.outputs[f"context_{service.port}"] = ctx_info
        return result
