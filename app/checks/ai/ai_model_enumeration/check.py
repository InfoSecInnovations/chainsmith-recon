"""
app/checks/ai/ai_model_enumeration/check.py - Model Enumeration

Enumerate available models by sending chat requests with different
model parameter values.

**Probe/grade.** The probe sends the test prompt under each
candidate model name and records the answers; `grade()` re-reads them, sorts the
accepted names from the recognised-but-unavailable ones, and walks the original
severity ladder. Which model a recorded exchange tested is read back off the
`model` field of its own request body (§0.13), so the accepted list cannot drift
from what was actually asked. `_reading()` is the one parser both halves call.
"""

from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Candidate, Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import safe_json

JSON_HEADERS = {"Content-Type": "application/json"}

#: Accepted names that mean a non-production model is reachable.
INTERNAL_MODELS = ("staging", "test", "internal", "base")


class ModelEnumerationCheck(BaseCheck):
    """Enumerate available models via the model parameter in chat requests."""

    name = "ai_model_enumeration"
    description = "Enumerate available models by testing different model parameter values"
    intrusive = False

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["available_models"]

    sequential = True

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

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        for endpoint_info in context.get("chat_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))
            api_format = endpoint_info.get("api_format", "unknown")

            try:
                candidate = self.create_candidate(host=service.host, target=service, target_url=url)
                await self._enumerate(url, service, api_format, context, candidate, scan_id)
                result.candidates.append(candidate)

                result.outputs["available_models"] = self._reading(candidate.exchanges)["available"]
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _enumerate(
        self,
        url: str,
        service: Service,
        api_format: str,
        context: dict,
        candidate: Candidate,
        scan_id: str,
    ) -> None:
        """Send the prompt under each candidate model name, recording each."""
        models_to_test = self._select_models(service, api_format, context)

        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        async with AsyncHttpClient(cfg) as client:
            for model_name in models_to_test:
                await self._rate_limit()

                body = self._build_request(model_name, api_format)
                resp = await client.post(url, json=body, headers=JSON_HEADERS)

                candidate.attach(
                    exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=candidate.host,
                        method="POST",
                        request_headers=JSON_HEADERS,
                        request_json=body,
                    )
                )

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Walk the original enumeration ladder over the recorded attempts."""
        reading = self._reading(list(evidence))
        available = reading["available"]
        ids = evidence.ids()

        verdicts: list[Verdict] = []

        internal = [m for m in available if m in INTERNAL_MODELS]
        if internal:
            verdicts.append(
                Verdict(
                    severity="high",
                    # A generic name like `internal` accepted with a 200 is a
                    # reachable model, but the name is our label, not the
                    # target's — a server that maps every unknown model to its
                    # default answers `internal` and `staging` identically to
                    # `gpt-4`. Whether these are genuinely distinct models is
                    # the doubt, so this is confident but not conclusive.
                    confidence=0.7,
                    discriminator="internal-model",
                    title=f"Internal/staging model accessible: {', '.join(internal)}",
                    description=(
                        "Internal or staging models are accessible and may have weaker guardrails"
                    ),
                    evidence=f"Models responding: {', '.join(internal)}",
                    reasoning=(
                        f"the model name(s) {', '.join(internal)} were accepted with 200; a "
                        "server that silently falls back to its default for any unknown model "
                        "would accept them without their being distinct models"
                    ),
                    signals={"internal_models": internal, "available": available},
                    raw_data={"internal_models": internal},
                    evidence_ids=ids,
                )
            )

        if available:
            distinct = self._looks_distinct(reading)
            verdicts.append(
                Verdict(
                    severity="medium" if len(available) > 1 else "info",
                    confidence=0.85 if distinct else 0.5,
                    discriminator="models-enumerated",
                    title=f"{len(available)} models available",
                    description=f"Enumerated models: {', '.join(available)}",
                    evidence=f"Available: {', '.join(available)}",
                    reasoning=(
                        f"{len(available)} names answered 200"
                        + (
                            "; some names were rejected with 404, so the endpoint discriminates "
                            "between models and the accepted set is real"
                            if distinct
                            else "; but no name was rejected, so the endpoint may accept the "
                            "`model` field and ignore it — the count could be an artefact of the "
                            "wordlist rather than an inventory"
                        )
                    ),
                    signals={
                        "available": available,
                        "recognized_unavailable": reading["recognized_unavailable"],
                    },
                    raw_data={
                        "available": available,
                        "recognized_unavailable": reading["recognized_unavailable"],
                    },
                    evidence_ids=ids,
                )
            )
        else:
            verdicts.append(
                Verdict(
                    severity="info",
                    confidence=0.8,
                    discriminator="no-enum",
                    title="Single model available (no enumeration possible)",
                    description="Model parameter is not accepted or only one model is configured",
                    evidence=f"Tested {reading['tested']} model names, none accepted",
                    reasoning=(
                        "no candidate model name drew a 200; the endpoint either ignores the "
                        "model field or exposes a single model"
                    ),
                    signals={"tested": reading["tested"]},
                    evidence_ids=ids,
                )
            )

        return verdicts

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict:
        """Sort recorded attempts by the `model` each requested and its status."""
        available: list[str] = []
        recognized_unavailable: list[str] = []
        tested = 0

        for exchange in exchanges:
            model_name = self._model_of(exchange)
            if model_name is None:
                continue
            tested += 1

            if exchange.error:
                continue

            if exchange.response_status == 200:
                available.append(model_name)
            elif exchange.response_status == 404:
                body = safe_json(exchange.response_body or "") or {}
                err_msg = str(body.get("error", ""))
                if model_name in err_msg or "model" in err_msg.lower():
                    recognized_unavailable.append(model_name)

        return {
            "available": available,
            "recognized_unavailable": recognized_unavailable,
            "tested": tested,
        }

    def _model_of(self, exchange: Exchange) -> str | None:
        """The model name a recorded request asked for."""
        body = safe_json(exchange.request_body or "")
        if isinstance(body, dict):
            model = body.get("model")
            if isinstance(model, str):
                return model
        return None

    def _looks_distinct(self, reading: dict) -> bool:
        """True when the endpoint rejected at least one model — evidence that
        the accepted names are real rather than an ignored parameter."""
        return bool(reading["recognized_unavailable"])

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
