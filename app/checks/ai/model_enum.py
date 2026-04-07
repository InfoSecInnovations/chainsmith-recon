"""
app/checks/ai/model_enum.py - Model Enumeration

Enumerate available models by sending chat requests with different
model parameter values.
"""

from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation
from app.lib.parsing import safe_json


class ModelEnumerationCheck(BaseCheck):
    """Enumerate available models via the model parameter in chat requests."""

    name = "model_enumeration"
    description = "Enumerate available models by testing different model parameter values"
    intrusive = False

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["available_models"]

    timeout_seconds = 120.0
    sequential = True
    requests_per_second = 2.0

    reason = (
        "Reveals the full model inventory; internal/staging models often have weaker guardrails"
    )
    references = ["OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure"]
    techniques = ["model enumeration", "service fingerprinting"]

    # Models grouped by provider
    MODEL_WORDLISTS = {
        "openai": [
            "gpt-4",
            "gpt-4-turbo",
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-3.5-turbo",
            "o1",
            "o1-mini",
            "o3-mini",
        ],
        "anthropic": [
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "claude-3-5-sonnet-20241022",
            "claude-sonnet-4-20250514",
            "claude-opus-4-20250514",
        ],
        "meta": [
            "llama2",
            "llama-2-7b",
            "llama-2-13b",
            "llama-2-70b",
            "llama3",
            "llama-3-8b",
            "llama-3-70b",
            "llama-3.1-405b",
        ],
        "mistral": [
            "mistral-7b",
            "mixtral-8x7b",
            "mistral-large",
            "mistral-medium",
        ],
        "generic": [
            "default",
            "base",
            "production",
            "staging",
            "test",
            "internal",
        ],
    }

    TEST_PROMPT = "Say hello in one word."

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        for endpoint_info in context.get("chat_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))
            api_format = endpoint_info.get("api_format", "unknown")

            try:
                er = await self._enumerate_models(url, service, api_format, context)
                result.observations.extend(er.observations)
                result.outputs.update(er.outputs)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _enumerate_models(
        self, url: str, service: Service, api_format: str, context: dict
    ) -> CheckResult:
        result = CheckResult(success=True)
        available = []
        recognized_unavailable = []

        # Select model list based on framework fingerprint
        models_to_test = self._select_models(service, api_format, context)

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for model_name in models_to_test:
                    await self._rate_limit()

                    body = self._build_request(model_name, api_format)

                    resp = await client.post(
                        url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                    )

                    if resp.error:
                        continue

                    if resp.status_code == 200:
                        available.append(model_name)
                    elif resp.status_code == 404:
                        # Model recognized but unavailable
                        resp_body = safe_json(resp.body) or {}
                        err_msg = str(resp_body.get("error", ""))
                        if model_name in err_msg or "model" in err_msg.lower():
                            recognized_unavailable.append(model_name)

        except Exception as e:
            result.errors.append(f"{url}: {e}")
            return result

        host = service.host

        internal_models = [m for m in available if m in ("staging", "test", "internal", "base")]

        if internal_models:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Internal/staging model accessible: {', '.join(internal_models)}",
                    description="Internal or staging models are accessible and may have weaker guardrails",
                    severity="high",
                    evidence=f"Models responding: {', '.join(internal_models)}",
                    host=host,
                    discriminator="internal-model",
                    target=service,
                    target_url=url,
                    raw_data={"internal_models": internal_models},
                )
            )

        if available:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"{len(available)} models available",
                    description=f"Enumerated models: {', '.join(available)}",
                    severity="medium" if len(available) > 1 else "info",
                    evidence=f"Available: {', '.join(available)}",
                    host=host,
                    discriminator="models-enumerated",
                    target=service,
                    target_url=url,
                    raw_data={
                        "available": available,
                        "recognized_unavailable": recognized_unavailable,
                    },
                )
            )
        else:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="Single model available (no enumeration possible)",
                    description="Model parameter is not accepted or only one model is configured",
                    severity="info",
                    evidence=f"Tested {len(models_to_test)} model names, none accepted",
                    host=host,
                    discriminator="no-enum",
                    target=service,
                    target_url=url,
                )
            )

        result.outputs["available_models"] = available
        return result

    def _select_models(self, service: Service, api_format: str, context: dict) -> list[str]:
        """Select model names to test based on detected framework."""
        framework_key = f"ai_framework_{service.port}"
        framework = context.get(framework_key, {})
        detected = (
            str(framework.get("framework", "")).lower() if isinstance(framework, dict) else ""
        )

        # Always test generic names
        models = list(self.MODEL_WORDLISTS["generic"])

        # Add provider-specific models based on framework or api_format
        if "openai" in detected or api_format == "openai":
            models.extend(self.MODEL_WORDLISTS["openai"])
        elif "anthropic" in detected or api_format == "anthropic":
            models.extend(self.MODEL_WORDLISTS["anthropic"])
        elif "ollama" in detected or api_format == "ollama":
            models.extend(self.MODEL_WORDLISTS["meta"])
            models.extend(self.MODEL_WORDLISTS["mistral"])
        else:
            # Unknown framework — test a sampling from each provider
            for provider_models in self.MODEL_WORDLISTS.values():
                models.extend(provider_models[:3])

        return list(dict.fromkeys(models))  # deduplicate, preserve order

    def _build_request(self, model_name: str, api_format: str) -> dict:
        """Build a chat request with the given model name."""
        if api_format == "openai" or api_format == "anthropic":
            return {
                "model": model_name,
                "messages": [{"role": "user", "content": self.TEST_PROMPT}],
                "max_tokens": 10,
            }
        elif api_format == "ollama":
            return {"model": model_name, "prompt": self.TEST_PROMPT}
        else:
            return {"model": model_name, "message": self.TEST_PROMPT}
