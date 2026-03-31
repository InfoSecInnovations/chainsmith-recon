"""
app/checks/web/cors.py - CORS Misconfiguration Testing

Test for overly permissive CORS configurations.
"""

from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict
from app.lib.findings import build_finding
from app.lib.evidence import fmt_cors_evidence


class CorsCheck(ServiceIteratingCheck):
    """Test for CORS misconfigurations."""

    name = "cors_check"
    description = "Test for overly permissive CORS configurations"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["cors_findings"]
    service_types = ["http", "html", "api", "ai"]

    timeout_seconds = 30.0

    reason = "CORS misconfigurations can allow malicious sites to steal data via a user's browser"
    references = ["OWASP WSTG-CLNT-07", "CWE-942", "PortSwigger CORS"]
    techniques = ["configuration testing", "CORS exploitation"]

    TEST_ORIGINS = [
        "https://evil.attacker.com",
        "null",   # null origin sandbox bypass
    ]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for origin in self.TEST_ORIGINS:
                    resp = await client.options(
                        service.url,
                        headers={
                            "Origin": origin,
                            "Access-Control-Request-Method": "POST",
                            "Access-Control-Request-Headers": "Content-Type",
                        },
                    )

                    if resp.error:
                        result.errors.append(f"CORS OPTIONS {service.url}: {resp.error}")
                        continue

                    headers_lower = extract_headers_dict(resp.headers)
                    acao = headers_lower.get("access-control-allow-origin", "")
                    acac = headers_lower.get("access-control-allow-credentials", "").lower()

                    if acao == "*":
                        severity = "high" if acac == "true" else "medium"
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title="CORS wildcard origin",
                            description="Server allows any origin — may allow cross-origin data theft",
                            severity=severity,
                            evidence=fmt_cors_evidence(origin, acao) + f" | credentials: {acac or 'not set'}",
                            host=service.host,
                            discriminator="wildcard-origin",
                            target=service,
                            references=["CWE-942"],
                        ))
                        break

                    elif acao == origin and origin != "null":
                        severity = "high" if acac == "true" else "medium"
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title="CORS reflects arbitrary origin",
                            description=f"Server reflects attacker-controlled origin: {origin}",
                            severity=severity,
                            evidence=fmt_cors_evidence(origin, acao) + f" | credentials: {acac or 'not set'}",
                            host=service.host,
                            discriminator="reflected-origin",
                            target=service,
                            references=["CWE-942"],
                        ))
                        break

                    elif acao == "null":
                        result.findings.append(build_finding(
                            check_name=self.name,
                            title="CORS allows null origin",
                            description="Server accepts 'null' origin — sandbox iframe bypass possible",
                            severity="medium",
                            evidence=fmt_cors_evidence("null", "null"),
                            host=service.host,
                            discriminator="null-origin",
                            target=service,
                            references=["CWE-942"],
                        ))
                        break

        except Exception as e:
            result.errors.append(f"CORS check on {service.url}: {e}")

        return result
