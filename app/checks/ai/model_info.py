"""
app/checks/ai/model_info.py - Model Information Disclosure

Discover endpoints that expose model information, versions, and configuration.
"""

from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.evidence import fmt_endpoint_evidence
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import make_observation_id_hashed
from app.lib.parsing import safe_json


class ModelInfoCheck(ServiceIteratingCheck):
    """Check for model information disclosure endpoints."""

    name = "model_info_check"
    description = "Discover endpoints that expose model information and configuration"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["model_info"]
    service_types = ["ai", "api"]

    timeout_seconds = 30.0

    reason = "Model info endpoints reveal architecture, version, and configuration details useful for targeted attacks"
    references = ["OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure"]
    techniques = ["API enumeration", "model fingerprinting", "configuration discovery"]

    MODEL_PATHS = [
        "/v1/models",
        "/models",
        "/model/info",
        "/model-info",
        "/api/models",
        "/api/v1/models",
        "/api/tags",
        "/api/show",
        "/internal/model-admin",
        "/debug/model",
        "/admin/models",
        "/health",
        "/version",
        "/info",
        "/config",
        "/api/config",
        "/settings",
    ]

    SENSITIVE_FIELDS = [
        "api_key",
        "secret",
        "token",
        "password",
        "credential",
        "system_prompt",
        "base_prompt",
        "instruction",
        "internal",
        "private",
        "cost",
        "billing",
    ]

    HIGH_SEVERITY_PATH_KEYWORDS = ["internal", "admin", "debug"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in self.MODEL_PATHS:
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200:
                        continue

                    severity = "medium"
                    sensitive_found = []
                    model_details = {}

                    if any(kw in path.lower() for kw in self.HIGH_SEVERITY_PATH_KEYWORDS):
                        severity = "high"

                    data = safe_json(resp.body)
                    if data is not None:
                        body_str = str(data).lower()
                        for field in self.SENSITIVE_FIELDS:
                            if field in body_str:
                                sensitive_found.append(field)
                                severity = "high"

                        if isinstance(data, dict):
                            model_details = {
                                "models": data.get("data", data.get("models", [])),
                                "model_id": data.get("model_id", data.get("model", "")),
                                "version": data.get("version", ""),
                                "max_tokens": data.get("max_tokens", data.get("max_model_len", "")),
                                "context_length": data.get("context_length", ""),
                            }
                        elif isinstance(data, list):
                            model_details["models"] = data

                    evidence = fmt_endpoint_evidence(url, resp.status_code)
                    if sensitive_found:
                        evidence += f" | Sensitive fields: {', '.join(sensitive_found)}"
                    if model_details.get("model_id"):
                        evidence += f" | Model: {model_details['model_id']}"

                    observation_id = make_observation_id_hashed(
                        self.name, service.host, "info-endpoint", path
                    )
                    from app.checks.base import Observation

                    result.observations.append(
                        Observation(
                            id=observation_id,
                            title=f"Model info endpoint: {path}",
                            description="Endpoint exposes model information and configuration",
                            severity=severity,
                            evidence=evidence,
                            target=service,
                            target_url=url,
                            check_name=self.name,
                            raw_data={
                                "model_details": model_details,
                                "sensitive_fields": sensitive_found,
                                "response_preview": resp.body[:500],
                            },
                        )
                    )

                    result.outputs[f"model_info_{service.port}"] = model_details

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result
