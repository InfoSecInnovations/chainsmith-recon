"""
Adjudicator Agent

Challenges and debates the risk criticality of verified findings.
Produces adjudicated_risk annotations without modifying original findings.

Three approaches available:
  - structured_challenge: Devil's advocate single LLM call (cheapest)
  - adversarial_debate: Prosecutor + defender + judge (3 LLM calls, most thorough)
  - evidence_rubric: CVSS-like structured scoring (1 LLM call, most deterministic)
  - auto: Tiered by severity (default)
"""

import json
import logging
from collections.abc import Awaitable, Callable

from app.lib.llm import LLMResponse, get_llm_client
from app.models import (
    AdjudicatedRisk,
    AdjudicationApproach,
    AgentEvent,
    AgentType,
    EventImportance,
    EventType,
    Finding,
    FindingSeverity,
    OperatorAssetContext,
    OperatorContext,
)

logger = logging.getLogger(__name__)

# ─── System Prompts ──────────────────────────────────────────────

STRUCTURED_CHALLENGE_PROMPT = """\
You are a security severity adjudicator. Your job is to challenge the assigned \
severity of a security finding by arguing as a devil's advocate.

Given a finding with its evidence and context, argue why the current severity \
rating might be WRONG — either too high or too low. Then make a final decision.

RULES:
1. Consider attack vector, complexity, privileges required, and impact scope.
2. If operator context is provided (asset exposure, criticality), factor it in.
3. Be practical — a theoretical attack on an internal-only service is less \
   severe than the same attack on an internet-facing production system.
4. Output your response as valid JSON only, no markdown fences.

OUTPUT FORMAT (JSON only):
{
  "challenge_argument": "Why the severity might be wrong...",
  "final_severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "rationale": "Brief explanation of final decision",
  "factors": {
    "attack_vector": "network|adjacent|local|physical",
    "complexity": "low|high",
    "privileges_required": "none|low|high",
    "impact": "critical|high|medium|low|none"
  }
}"""

ADVERSARIAL_PROSECUTOR_PROMPT = """\
You are a security severity PROSECUTOR. Your job is to argue that the finding's \
severity should be MAINTAINED or RAISED. Build the strongest case for why this \
finding is dangerous.

Consider: real-world exploitability, blast radius, data exposure, lateral \
movement potential, and any operator context provided.

Output your argument as valid JSON only, no markdown fences:
{
  "argument": "Your case for maintaining or raising severity...",
  "suggested_severity": "critical|high|medium|low|info",
  "key_factors": ["factor1", "factor2"]
}"""

ADVERSARIAL_DEFENDER_PROMPT = """\
You are a security severity DEFENDER. Your job is to argue that the finding's \
severity should be LOWERED. Build the strongest case for why this finding is \
less dangerous than it appears.

Consider: mitigating controls, limited attack surface, required preconditions, \
low impact in context, and any operator context provided.

Output your argument as valid JSON only, no markdown fences:
{
  "argument": "Your case for lowering severity...",
  "suggested_severity": "critical|high|medium|low|info",
  "key_factors": ["factor1", "factor2"]
}"""

ADVERSARIAL_JUDGE_PROMPT = """\
You are a security severity JUDGE. You have heard arguments from a prosecutor \
(arguing severity should stay or increase) and a defender (arguing it should \
decrease). Weigh both arguments and render a final verdict.

RULES:
1. Be impartial — evaluate the strength of each argument.
2. Factor in operator context if provided.
3. Output your verdict as valid JSON only, no markdown fences.

OUTPUT FORMAT (JSON only):
{
  "verdict": "The prosecution/defense argument is stronger because...",
  "final_severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "rationale": "Brief explanation of final decision",
  "factors": {
    "attack_vector": "network|adjacent|local|physical",
    "complexity": "low|high",
    "privileges_required": "none|low|high",
    "impact": "critical|high|medium|low|none"
  }
}"""

EVIDENCE_RUBRIC_PROMPT = """\
You are a security severity scorer. Rate the finding using a structured rubric. \
Do NOT free-form debate — map evidence to each factor and score it.

RUBRIC FACTORS (score each 0.0-1.0):
- exploitability: How easy is it to exploit? (0=theoretical, 1=trivially exploitable)
- impact: What damage can it cause? (0=none, 1=full compromise)
- reproducibility: How reliably can it be triggered? (0=rare, 1=always)
- asset_criticality: How important is the target asset? (0=dev/test, 1=production/critical)
- exposure: How accessible is the attack surface? (0=air-gapped, 1=internet-facing)

SEVERITY MAPPING (use average of all factors):
- >= 0.8: critical
- >= 0.6: high
- >= 0.4: medium
- >= 0.2: low
- < 0.2: info

Output your scores as valid JSON only, no markdown fences:
{
  "scores": {
    "exploitability": 0.0-1.0,
    "impact": 0.0-1.0,
    "reproducibility": 0.0-1.0,
    "asset_criticality": 0.0-1.0,
    "exposure": 0.0-1.0
  },
  "average_score": 0.0-1.0,
  "final_severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "rationale": "Brief explanation"
}"""


# ─── Agent ──────────────────────────────────────────────────────


class AdjudicatorAgent:
    """
    Challenges and debates severity ratings of verified findings.

    Read-only on scope and findings — produces adjudicated_risk annotations
    without modifying original data.
    """

    def __init__(
        self,
        event_callback: Callable[[AgentEvent], Awaitable[None]] | None = None,
        approach: AdjudicationApproach = AdjudicationApproach.AUTO,
    ):
        self.event_callback = event_callback
        self.approach = approach
        self.client = get_llm_client()
        self.is_running = False
        self.results: list[AdjudicatedRisk] = []

    async def emit(self, event: AgentEvent):
        """Emit event to callback."""
        if self.event_callback:
            await self.event_callback(event)

    async def adjudicate_findings(
        self,
        findings: list[Finding],
        operator_context: OperatorContext | None = None,
    ) -> list[AdjudicatedRisk]:
        """
        Adjudicate severity of verified findings.

        Args:
            findings: Verified findings to adjudicate.
            operator_context: Optional operator-declared asset context.

        Returns:
            List of AdjudicatedRisk results.
        """
        self.is_running = True
        self.results = []

        verified = [f for f in findings if f.status == "verified"]
        if not verified:
            logger.info("No verified findings to adjudicate")
            self.is_running = False
            return []

        await self.emit(
            AgentEvent(
                event_type=EventType.ADJUDICATION_START,
                agent=AgentType.ADJUDICATOR,
                importance=EventImportance.MEDIUM,
                message=f"Adjudicator starting severity review of {len(verified)} verified findings...",
                details={"total_findings": len(verified), "approach": self.approach},
            )
        )

        upheld = 0
        adjusted = 0

        for finding in verified:
            if not self.is_running:
                break

            try:
                result = await self._adjudicate_single(finding, operator_context)
                self.results.append(result)

                if result.original_severity == result.adjudicated_severity:
                    upheld += 1
                    event_type = EventType.SEVERITY_UPHELD
                    importance = EventImportance.LOW
                    msg = f"Severity upheld for {finding.id}: {result.original_severity}"
                else:
                    adjusted += 1
                    event_type = EventType.SEVERITY_ADJUSTED
                    importance = EventImportance.HIGH
                    msg = (
                        f"Severity adjusted for {finding.id}: "
                        f"{result.original_severity} -> {result.adjudicated_severity}"
                    )

                await self.emit(
                    AgentEvent(
                        event_type=event_type,
                        agent=AgentType.ADJUDICATOR,
                        importance=importance,
                        message=msg,
                        finding_id=finding.id,
                        details={
                            "original": result.original_severity,
                            "adjudicated": result.adjudicated_severity,
                            "confidence": result.confidence,
                            "approach": result.approach_used,
                        },
                    )
                )
            except Exception as e:
                logger.warning(f"Failed to adjudicate finding {finding.id}: {e}")
                await self.emit(
                    AgentEvent(
                        event_type=EventType.ERROR,
                        agent=AgentType.ADJUDICATOR,
                        importance=EventImportance.MEDIUM,
                        message=f"Adjudication failed for {finding.id}: {e}",
                        finding_id=finding.id,
                    )
                )

        await self.emit(
            AgentEvent(
                event_type=EventType.ADJUDICATION_COMPLETE,
                agent=AgentType.ADJUDICATOR,
                importance=EventImportance.MEDIUM,
                message=(
                    f"Adjudication complete: {upheld} upheld, {adjusted} adjusted "
                    f"out of {len(verified)} findings"
                ),
                details={
                    "total": len(verified),
                    "upheld": upheld,
                    "adjusted": adjusted,
                    "approach": self.approach,
                },
            )
        )

        self.is_running = False
        return self.results

    def stop(self):
        """Stop the adjudicator."""
        self.is_running = False

    # ─── Internal ────────────────────────────────────────────────

    async def _adjudicate_single(
        self,
        finding: Finding,
        operator_context: OperatorContext | None,
    ) -> AdjudicatedRisk:
        """Adjudicate a single finding using the resolved approach."""
        approach = self._resolve_approach(finding)
        asset_context = self._match_asset_context(finding, operator_context)
        context_str = self._format_context(finding, asset_context)

        if approach == AdjudicationApproach.STRUCTURED_CHALLENGE:
            return await self._run_structured_challenge(finding, context_str)
        elif approach == AdjudicationApproach.ADVERSARIAL_DEBATE:
            return await self._run_adversarial_debate(finding, context_str)
        elif approach == AdjudicationApproach.EVIDENCE_RUBRIC:
            return await self._run_evidence_rubric(finding, context_str)
        else:
            return await self._run_structured_challenge(finding, context_str)

    def _resolve_approach(self, finding: Finding) -> AdjudicationApproach:
        """For 'auto' mode, pick approach based on severity tier."""
        if self.approach != AdjudicationApproach.AUTO:
            return self.approach

        severity = finding.severity
        if severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL):
            return AdjudicationApproach.ADVERSARIAL_DEBATE
        elif severity == FindingSeverity.MEDIUM:
            return AdjudicationApproach.EVIDENCE_RUBRIC
        else:
            return AdjudicationApproach.STRUCTURED_CHALLENGE

    def _match_asset_context(
        self,
        finding: Finding,
        operator_context: OperatorContext | None,
    ) -> OperatorAssetContext | None:
        """Match a finding to operator-declared asset context."""
        if not operator_context or not operator_context.assets:
            return None

        target = finding.target_url or finding.target_service or ""
        target_lower = target.lower()

        for asset in operator_context.assets:
            domain = asset.domain.lower()
            if domain.startswith("*."):
                base = domain[2:]
                if base in target_lower:
                    return asset
            elif domain in target_lower:
                return asset

        # Return defaults as a synthetic asset context
        if operator_context.defaults:
            return OperatorAssetContext(
                domain="*",
                exposure=operator_context.defaults.get("exposure", "unknown"),
                criticality=operator_context.defaults.get("criticality", "medium"),
            )
        return None

    def _format_context(
        self,
        finding: Finding,
        asset_context: OperatorAssetContext | None,
    ) -> str:
        """Format finding + asset context into a prompt string."""
        parts = [
            f"Finding ID: {finding.id}",
            f"Title: {finding.title}",
            f"Description: {finding.description}",
            f"Current Severity: {finding.severity}",
            f"Confidence: {finding.confidence}",
            f"Target: {finding.target_url or finding.target_service or 'unknown'}",
        ]
        if finding.evidence_summary:
            parts.append(f"Evidence: {finding.evidence_summary}")
        if finding.exploitation_techniques:
            parts.append(f"Exploitation Techniques: {', '.join(finding.exploitation_techniques)}")

        if asset_context:
            parts.append("")
            parts.append("OPERATOR CONTEXT:")
            parts.append(f"  Asset Exposure: {asset_context.exposure}")
            parts.append(f"  Asset Criticality: {asset_context.criticality}")
            if asset_context.notes:
                parts.append(f"  Notes: {asset_context.notes}")

        return "\n".join(parts)

    async def _run_structured_challenge(
        self, finding: Finding, context: str
    ) -> AdjudicatedRisk:
        """Single LLM call — devil's advocate challenge."""
        response = await self.client.chat(
            prompt=f"Evaluate this finding:\n\n{context}",
            system=STRUCTURED_CHALLENGE_PROMPT,
        )
        return self._parse_single_response(
            finding, response, AdjudicationApproach.STRUCTURED_CHALLENGE
        )

    async def _run_adversarial_debate(
        self, finding: Finding, context: str
    ) -> AdjudicatedRisk:
        """Three LLM calls — prosecutor, defender, judge."""
        # Call 1: Prosecutor argues to maintain/raise
        prosecution = await self.client.chat(
            prompt=f"Evaluate this finding:\n\n{context}",
            system=ADVERSARIAL_PROSECUTOR_PROMPT,
        )

        # Call 2: Defender argues to lower
        defense = await self.client.chat(
            prompt=f"Evaluate this finding:\n\n{context}",
            system=ADVERSARIAL_DEFENDER_PROMPT,
        )

        # Call 3: Judge weighs both arguments
        judge_prompt = (
            f"Finding under review:\n\n{context}\n\n"
            f"PROSECUTION ARGUMENT:\n{prosecution.content}\n\n"
            f"DEFENSE ARGUMENT:\n{defense.content}"
        )
        verdict = await self.client.chat(
            prompt=judge_prompt,
            system=ADVERSARIAL_JUDGE_PROMPT,
        )
        return self._parse_single_response(
            finding, verdict, AdjudicationApproach.ADVERSARIAL_DEBATE
        )

    async def _run_evidence_rubric(
        self, finding: Finding, context: str
    ) -> AdjudicatedRisk:
        """Single LLM call — structured rubric scoring."""
        response = await self.client.chat(
            prompt=f"Score this finding using the rubric:\n\n{context}",
            system=EVIDENCE_RUBRIC_PROMPT,
        )
        return self._parse_rubric_response(finding, response)

    def _parse_single_response(
        self,
        finding: Finding,
        response: LLMResponse,
        approach: AdjudicationApproach,
    ) -> AdjudicatedRisk:
        """Parse a structured challenge or adversarial judge response."""
        if not response.success:
            logger.warning(f"LLM call failed for {finding.id}: {response.error}")
            return self._fallback_result(finding, approach, response.error or "LLM call failed")

        try:
            data = json.loads(self._clean_json(response.content))
        except (json.JSONDecodeError, ValueError):
            logger.warning(f"Failed to parse LLM JSON for {finding.id}")
            return self._fallback_result(finding, approach, "Failed to parse LLM response")

        severity_str = data.get("final_severity", finding.severity).lower()
        try:
            adjudicated_severity = FindingSeverity(severity_str)
        except ValueError:
            adjudicated_severity = finding.severity

        return AdjudicatedRisk(
            finding_id=finding.id,
            original_severity=finding.severity,
            adjudicated_severity=adjudicated_severity,
            confidence=float(data.get("confidence", 0.5)),
            approach_used=approach,
            rationale=data.get("rationale", ""),
            factors=data.get("factors", {}),
        )

    def _parse_rubric_response(
        self,
        finding: Finding,
        response: LLMResponse,
    ) -> AdjudicatedRisk:
        """Parse an evidence rubric response with scores."""
        if not response.success:
            logger.warning(f"LLM call failed for {finding.id}: {response.error}")
            return self._fallback_result(
                finding, AdjudicationApproach.EVIDENCE_RUBRIC, response.error or "LLM call failed"
            )

        try:
            data = json.loads(self._clean_json(response.content))
        except (json.JSONDecodeError, ValueError):
            logger.warning(f"Failed to parse rubric JSON for {finding.id}")
            return self._fallback_result(
                finding, AdjudicationApproach.EVIDENCE_RUBRIC, "Failed to parse rubric response"
            )

        scores = data.get("scores", {})
        severity_str = data.get("final_severity", finding.severity).lower()
        try:
            adjudicated_severity = FindingSeverity(severity_str)
        except ValueError:
            adjudicated_severity = finding.severity

        return AdjudicatedRisk(
            finding_id=finding.id,
            original_severity=finding.severity,
            adjudicated_severity=adjudicated_severity,
            confidence=float(data.get("confidence", 0.5)),
            approach_used=AdjudicationApproach.EVIDENCE_RUBRIC,
            rationale=data.get("rationale", ""),
            factors=scores,
        )

    @staticmethod
    def _fallback_result(
        finding: Finding, approach: AdjudicationApproach, reason: str
    ) -> AdjudicatedRisk:
        """Return a fallback result that upholds the original severity."""
        return AdjudicatedRisk(
            finding_id=finding.id,
            original_severity=finding.severity,
            adjudicated_severity=finding.severity,
            confidence=0.0,
            approach_used=approach,
            rationale=f"Adjudication inconclusive — severity upheld. Reason: {reason}",
            factors={},
        )

    @staticmethod
    def _clean_json(text: str) -> str:
        """Strip markdown fences and whitespace from LLM JSON output."""
        cleaned = text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            # Remove first line (```json) and last line (```)
            lines = [line for line in lines if not line.strip().startswith("```")]
            cleaned = "\n".join(lines)
        return cleaned.strip()
