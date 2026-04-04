"""
app/checks/ai/auth_bypass.py - API Key/Auth Bypass on AI Endpoints

Test discovered chat endpoints with various authentication states to
identify auth bypass vulnerabilities.
"""

from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.ai_helpers import format_chat_request
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig


class AuthBypassCheck(BaseCheck):
    """Test AI endpoint authentication for bypass vulnerabilities."""

    name = "auth_bypass"
    description = "Test AI endpoints with various auth states to detect bypass vulnerabilities"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["auth_status"]

    timeout_seconds = 60.0
    sequential = True
    requests_per_second = 2.0

    reason = "Many internal AI services have no auth or accept any key"
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "OWASP API Security Top 10 - API2 Broken Authentication",
    ]
    techniques = ["auth bypass", "credential testing"]

    # Auth states to test: (label, headers_dict)
    AUTH_TESTS = [
        ("no_auth", {}),
        ("empty_bearer", {"Authorization": "Bearer "}),
        ("default_sk_test", {"Authorization": "Bearer sk-test"}),
        ("default_demo", {"Authorization": "Bearer demo"}),
        ("default_empty_key", {"Authorization": "Bearer EMPTY"}),
        ("default_test_key", {"Authorization": "Bearer test-key"}),
        ("default_no_key", {"Authorization": "Bearer sk-no-key-required"}),
        ("basic_test", {"Authorization": "Basic dGVzdDp0ZXN0"}),
    ]

    TEST_PROMPT = "Say hello."

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        for endpoint_info in context.get("chat_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))
            api_format = endpoint_info.get("api_format", "unknown")

            try:
                ar = await self._test_auth(url, service, api_format)
                result.findings.extend(ar.findings)
                result.outputs.update(ar.outputs)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _test_auth(
        self,
        url: str,
        service: Service,
        api_format: str,
    ) -> CheckResult:
        result = CheckResult(success=True)
        host = service.host
        accepted = []
        rejected = []

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for label, auth_headers in self.AUTH_TESTS:
                    await self._rate_limit()

                    headers = {"Content-Type": "application/json"}
                    headers.update(auth_headers)

                    body = format_chat_request(self.TEST_PROMPT, api_format)
                    resp = await client.post(url, json=body, headers=headers)

                    if resp.error:
                        continue

                    if resp.status_code == 200:
                        accepted.append(label)
                    elif resp.status_code in (401, 403):
                        rejected.append(label)

        except Exception as e:
            result.errors.append(f"{url}: {e}")
            return result

        auth_info = {
            "accepted": accepted,
            "rejected": rejected,
        }

        # No auth at all works
        if "no_auth" in accepted:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="AI endpoint requires no authentication",
                    description="Chat endpoint responds to requests without any auth headers",
                    severity="critical",
                    evidence=f"No auth required. Accepted: {', '.join(accepted)}",
                    host=host,
                    discriminator="no-auth-required",
                    target=service,
                    target_url=url,
                    raw_data=auth_info,
                    references=self.references,
                )
            )
        elif "empty_bearer" in accepted:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="Auth bypass: empty Bearer token accepted",
                    description="Endpoint responds to requests with an empty Bearer token",
                    severity="high",
                    evidence=f"Empty bearer accepted. All accepted: {', '.join(accepted)}",
                    host=host,
                    discriminator="empty-bearer-bypass",
                    target=service,
                    target_url=url,
                    raw_data=auth_info,
                    references=self.references,
                )
            )
        elif any(label.startswith("default_") for label in accepted):
            default_accepted = [a for a in accepted if a.startswith("default_")]
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Default API key accepted: {', '.join(default_accepted)}",
                    description="Endpoint accepts well-known default or test API keys",
                    severity="critical",
                    evidence=f"Default keys accepted: {', '.join(default_accepted)}",
                    host=host,
                    discriminator="default-key-accepted",
                    target=service,
                    target_url=url,
                    raw_data=auth_info,
                    references=self.references,
                )
            )
        elif "basic_test" in accepted:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="Auth bypass: Basic test:test credentials accepted",
                    description="Endpoint accepts Basic auth with test:test credentials",
                    severity="high",
                    evidence="Basic dGVzdDp0ZXN0 (test:test) accepted",
                    host=host,
                    discriminator="basic-test-bypass",
                    target=service,
                    target_url=url,
                    raw_data=auth_info,
                    references=self.references,
                )
            )
        else:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title="Authentication enforced",
                    description=f"All {len(self.AUTH_TESTS)} bypass attempts rejected",
                    severity="info",
                    evidence=f"Rejected: {len(rejected)}/{len(self.AUTH_TESTS)} attempts",
                    host=host,
                    discriminator="auth-enforced",
                    target=service,
                    target_url=url,
                )
            )

        result.outputs[f"auth_status_{service.port}"] = auth_info
        return result
