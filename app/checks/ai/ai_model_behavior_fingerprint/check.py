"""
app/checks/ai/ai_model_behavior_fingerprint/check.py - Model Behavior Fingerprinting

Identify the actual underlying model by analyzing response patterns and
known behavioral signatures.

**Probe/grade.** The probe asks five behavioural questions
and records the answers; `grade()` re-reads them, rebuilds the `{test_id: text}`
map the analysis works over, and returns up to three verdicts — self-identified
family, a possible identity mismatch, and any reported knowledge cutoff.
`_responses_from()` is the one parser both halves call (§0.12); which test a
recorded answer belongs to is read back off its own prompt, not the send order.
"""

import re
from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Candidate, Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.ai_helpers import (
    dialect_from_request,
    format_chat_request,
    prompt_from_request,
    response_text_from,
)
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}


class ModelBehaviorFingerprintCheck(BaseCheck):
    """Identify the underlying model via behavioral signatures."""

    name = "ai_model_behavior_fingerprint"
    description = (
        "Identify the actual underlying model from response patterns and behavioral signatures"
    )
    intrusive = False

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["model_identity"]

    sequential = True

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
                await self._probe_fingerprint(url, api_format, candidate, scan_id)
                result.candidates.append(candidate)

                responses = self._responses_from(candidate.exchanges)
                if responses:
                    result.outputs[f"model_identity_{service.port}"] = self._determine_identity(
                        responses
                    )
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _probe_fingerprint(
        self, url: str, api_format: str, candidate: Candidate, scan_id: str
    ) -> None:
        """Ask each fingerprint question, recording every answer."""
        cfg = HttpConfig(timeout_seconds=20.0, verify_ssl=False)
        async with AsyncHttpClient(cfg) as client:
            for _test_id, prompt, _ in self.FINGERPRINT_TESTS:
                await self._rate_limit()

                body = format_chat_request(prompt, api_format)
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
        """Up to three verdicts from the recorded behavioural answers."""
        responses = self._responses_from(list(evidence))
        if not responses:
            return []

        identity = self._determine_identity(responses)
        ids = evidence.ids()
        verdicts: list[Verdict] = []

        if identity.get("model_family"):
            verdicts.append(
                Verdict(
                    severity="info",
                    # A model asked what it is will say, and a wrapper can make
                    # it say anything — self-report is suggestive, not proof.
                    # This is why the check exists: to compare the claim against
                    # behaviour, which is the mismatch verdict below.
                    confidence=0.5,
                    discriminator="model-identity",
                    title=f"Model self-identifies as: {identity['model_family']}",
                    description=f"Behavioral fingerprinting suggests {identity['model_family']}",
                    evidence=self._format_evidence(identity, responses),
                    reasoning=(
                        "the model named its own family; a self-report is easily overridden by a "
                        "system prompt, so it is suggestive rather than conclusive"
                    ),
                    signals={"model_family": identity["model_family"]},
                    raw_data=identity,
                    evidence_ids=ids,
                )
            )

            if identity.get("possible_mismatch"):
                verdicts.append(
                    Verdict(
                        severity="low",
                        # A behavioural contradiction is a stronger signal than
                        # the self-report it contradicts — but the strawberry
                        # and last-letter tests are noisy, and a wrapper adding
                        # its own creator line also trips the creator check.
                        confidence=0.55,
                        discriminator="model-mismatch",
                        title=f"Model misrepresents identity: {identity['mismatch_detail']}",
                        description="Behavioral patterns inconsistent with claimed model identity",
                        evidence=identity["mismatch_detail"],
                        reasoning=(
                            "a behavioural answer contradicts the claimed family; the tokenisation "
                            "and creator tests are individually noisy, so this flags rather than "
                            "concludes misrepresentation"
                        ),
                        signals={"mismatch_detail": identity["mismatch_detail"]},
                        raw_data=identity,
                        evidence_ids=ids,
                    )
                )

        if identity.get("knowledge_cutoff"):
            verdicts.append(
                Verdict(
                    severity="info",
                    # The date was parsed from the response with a strict regex,
                    # but it is the model's self-report of its cutoff, which is
                    # frequently wrong or hallucinated.
                    confidence=0.6,
                    discriminator="model-cutoff",
                    title=f"Knowledge cutoff: {identity['knowledge_cutoff']}",
                    description="Model reports a training data cutoff date",
                    evidence=f"Cutoff: {identity['knowledge_cutoff']}",
                    reasoning=(
                        "a date was parsed from the model's own answer; models routinely misstate "
                        "or hallucinate their cutoff, so the value is a claim, not a measurement"
                    ),
                    signals={"knowledge_cutoff": identity["knowledge_cutoff"]},
                    evidence_ids=ids,
                )
            )

        return verdicts

    # ── The parser both halves share ─────────────────────────────────

    def _responses_from(self, exchanges: list[Exchange]) -> dict[str, str]:
        """Rebuild `{test_id: answer text}` from recorded exchanges.

        Each answer is matched to its test by the prompt the recorded request
        carried, so the map is correct regardless of order or which tests were
        skipped for a non-200.
        """
        # Built from the instance, not the class, so a test (or an operator)
        # that overrides FINGERPRINT_TESTS is still matched correctly.
        test_by_prompt = {prompt: test_id for test_id, prompt, _ in self.FINGERPRINT_TESTS}

        responses: dict[str, str] = {}
        for exchange in exchanges:
            if exchange.error or exchange.response_status != 200:
                continue
            prompt = prompt_from_request(exchange.request_body or "")
            test_id = test_by_prompt.get(prompt)
            if test_id is None:
                continue
            api_format = dialect_from_request(exchange.request_body or "")
            responses[test_id] = response_text_from(exchange, api_format)
        return responses

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
