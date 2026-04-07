"""
app/checks/ai/model_fingerprint.py - Model Behavior Fingerprinting

Identify the actual underlying model by analyzing response patterns and
known behavioral signatures.
"""

from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.lib.ai_helpers import extract_response_text, format_chat_request
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation
from app.lib.parsing import safe_json


class ModelBehaviorFingerprintCheck(BaseCheck):
    """Identify the underlying model via behavioral signatures."""

    name = "model_behavior_fingerprint"
    description = (
        "Identify the actual underlying model from response patterns and behavioral signatures"
    )
    intrusive = False

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["model_identity"]

    timeout_seconds = 90.0
    sequential = True
    requests_per_second = 1.0

    reason = (
        "Knowing the exact model helps prioritize attack techniques and reveals misrepresentation"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["model fingerprinting", "behavioral analysis"]

    # Each tuple: (test_id, prompt, analysis_fn_name)
    FINGERPRINT_TESTS = [
        (
            "self_identify",
            "What AI model are you? Answer with just your model name and version.",
            "_analyze_self_id",
        ),
        (
            "knowledge_cutoff",
            "What is your training data cutoff date? Answer with just the date.",
            "_analyze_cutoff",
        ),
        (
            "strawberry",
            "How many r's are in the word 'strawberry'? Answer with just the number.",
            "_analyze_strawberry",
        ),
        (
            "last_letter",
            "What is the last letter of the word 'lamp'? Answer with just the letter.",
            "_analyze_last_letter",
        ),
        (
            "creator",
            "Who created you? Answer in one sentence.",
            "_analyze_creator",
        ),
    ]

    # Known model identifiers in self-identification responses
    MODEL_SIGNATURES = {
        "gpt-4": ["gpt-4", "gpt4"],
        "gpt-3.5": ["gpt-3.5", "gpt3.5", "chatgpt"],
        "claude": ["claude"],
        "llama": ["llama", "meta"],
        "mistral": ["mistral", "mixtral"],
        "gemini": ["gemini", "google"],
        "command": ["command", "cohere"],
    }

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        for endpoint_info in context.get("chat_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))
            api_format = endpoint_info.get("api_format", "unknown")

            try:
                fr = await self._fingerprint_model(url, service, api_format, context)
                result.observations.extend(fr.observations)
                result.outputs.update(fr.outputs)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _fingerprint_model(
        self,
        url: str,
        service: Service,
        api_format: str,
        context: dict,
    ) -> CheckResult:
        result = CheckResult(success=True)
        host = service.host
        responses_data = {}

        cfg = HttpConfig(timeout_seconds=20.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for test_id, prompt, _ in self.FINGERPRINT_TESTS:
                    await self._rate_limit()

                    body = format_chat_request(prompt, api_format)
                    resp = await client.post(
                        url,
                        json=body,
                        headers={"Content-Type": "application/json"},
                    )

                    if resp.error or resp.status_code != 200:
                        continue

                    parsed = safe_json(resp.body) or {}
                    text = extract_response_text(parsed, api_format)
                    responses_data[test_id] = text

        except Exception as e:
            result.errors.append(f"{url}: {e}")
            return result

        if not responses_data:
            return result

        # Analyze collected responses
        identity = self._determine_identity(responses_data)

        # Check for misrepresentation
        framework_key = f"ai_framework_{service.port}"
        framework = context.get(framework_key, {})
        if isinstance(framework, dict):
            str(framework.get("framework", "")).lower()

        if identity.get("model_family"):
            # Self-identification observation
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Model self-identifies as: {identity['model_family']}",
                    description=f"Behavioral fingerprinting suggests {identity['model_family']}",
                    severity="info",
                    evidence=self._format_evidence(identity, responses_data),
                    host=host,
                    discriminator="model-identity",
                    target=service,
                    target_url=url,
                    raw_data=identity,
                )
            )

            # Check misrepresentation
            if identity.get("possible_mismatch"):
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"Model misrepresents identity: {identity['mismatch_detail']}",
                        description="Behavioral patterns inconsistent with claimed model identity",
                        severity="low",
                        evidence=identity["mismatch_detail"],
                        host=host,
                        discriminator="model-mismatch",
                        target=service,
                        target_url=url,
                        raw_data=identity,
                    )
                )

        if identity.get("knowledge_cutoff"):
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Knowledge cutoff: {identity['knowledge_cutoff']}",
                    description="Model reports a training data cutoff date",
                    severity="info",
                    evidence=f"Cutoff: {identity['knowledge_cutoff']}",
                    host=host,
                    discriminator="model-cutoff",
                    target=service,
                    target_url=url,
                )
            )

        result.outputs[f"model_identity_{service.port}"] = identity
        return result

    def _determine_identity(self, responses: dict[str, str]) -> dict:
        """Analyze all test responses to determine model identity."""
        identity = {
            "model_family": None,
            "knowledge_cutoff": None,
            "possible_mismatch": False,
            "mismatch_detail": None,
            "confidence": "low",
            "raw_responses": {k: v[:200] for k, v in responses.items()},
        }

        # Self-identification
        self_id = responses.get("self_identify", "").lower()
        for family, keywords in self.MODEL_SIGNATURES.items():
            if any(kw in self_id for kw in keywords):
                identity["model_family"] = family
                identity["confidence"] = "medium"
                break

        # Knowledge cutoff
        cutoff = responses.get("knowledge_cutoff", "")
        import re

        date_match = re.search(
            r"((?:january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{4}|\d{4}-\d{2})",
            cutoff,
            re.IGNORECASE,
        )
        if date_match:
            identity["knowledge_cutoff"] = date_match.group(1)

        # Strawberry test (known failure for GPT-3.5)
        strawberry = responses.get("strawberry", "").strip()
        if strawberry and identity["model_family"]:
            # Correct answer is 3
            if "2" in strawberry and identity["model_family"] in ("gpt-4", "claude"):
                identity["possible_mismatch"] = True
                identity["mismatch_detail"] = (
                    f"Claims to be {identity['model_family']} but failed "
                    f"strawberry test (answered {strawberry}, expected 3)"
                )

        # Creator analysis
        creator = responses.get("creator", "").lower()
        if identity["model_family"] and creator:
            creator_map = {
                "gpt-4": "openai",
                "gpt-3.5": "openai",
                "claude": "anthropic",
                "llama": "meta",
                "gemini": "google",
            }
            expected_creator = creator_map.get(identity["model_family"], "")
            if expected_creator and expected_creator not in creator:
                identity["possible_mismatch"] = True
                identity["mismatch_detail"] = (
                    f"Claims to be {identity['model_family']} but creator "
                    f"response doesn't mention {expected_creator}"
                )

        return identity

    def _format_evidence(self, identity: dict, responses: dict) -> str:
        parts = []
        if identity.get("model_family"):
            parts.append(f"Identified as: {identity['model_family']}")
        if identity.get("confidence"):
            parts.append(f"Confidence: {identity['confidence']}")
        if "self_identify" in responses:
            parts.append(f"Self-ID: {responses['self_identify'][:100]}")
        return " | ".join(parts)
