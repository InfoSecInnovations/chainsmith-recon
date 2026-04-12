"""
Adjudicator Agent

Challenges the risk criticality of verified observations using a structured
evidence rubric. Produces adjudicated_risk annotations without modifying
original observations.

Uses a CVSS-like scoring rubric (single LLM call per observation) for
deterministic, comparable results. See docs/future-ideas/adjudicator-strategies-reference.md
for alternative approaches considered and archived.
"""

import json
import logging
from collections.abc import Awaitable, Callable

from app.lib.llm import LLMClient, LLMResponse
from app.models import (
    AdjudicatedRisk,
    AdjudicationApproach,
    AgentEvent,
    ComponentType,
    EventImportance,
    EventType,
    Observation,
    ObservationSeverity,
    OperatorAssetContext,
    OperatorContext,
)

logger = logging.getLogger(__name__)

# ─── System Prompt ──────────────────────────────────────────────

EVIDENCE_RUBRIC_PROMPT = """\
You are a security severity scorer. Rate the observation using a structured rubric. \
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
    Challenges and debates severity ratings of verified observations.

    Read-only on scope and observations — produces adjudicated_risk annotations
    without modifying original data.
    """

    def __init__(
        self,
        client: LLMClient,
        event_callback: Callable[[AgentEvent], Awaitable[None]] | None = None,
    ):
        self.client = client
        self.event_callback = event_callback
        self.is_running = False
        self.results: list[AdjudicatedRisk] = []

    async def emit(self, event: AgentEvent):
        """Emit event to callback."""
        if self.event_callback:
            await self.event_callback(event)

    async def adjudicate_observations(
        self,
        observations: list[Observation],
        operator_context: OperatorContext | None = None,
    ) -> list[AdjudicatedRisk]:
        """
        Adjudicate severity of verified observations.

        Args:
            observations: Verified observations to adjudicate.
            operator_context: Optional operator-declared asset context.

        Returns:
            List of AdjudicatedRisk results.
        """
        self.is_running = True
        self.results = []

        verified = [f for f in observations if f.status == "verified"]
        if not verified:
            logger.info("No verified observations to adjudicate")
            self.is_running = False
            return []

        await self.emit(
            AgentEvent(
                event_type=EventType.ADJUDICATION_START,
                agent=ComponentType.ADJUDICATOR,
                importance=EventImportance.MEDIUM,
                message=f"Adjudicator starting severity review of {len(verified)} verified observations...",
                details={
                    "total_observations": len(verified),
                    "approach": AdjudicationApproach.EVIDENCE_RUBRIC,
                },
            )
        )

        upheld = 0
        adjusted = 0

        for observation in verified:
            if not self.is_running:
                break

            try:
                result = await self._adjudicate_single(observation, operator_context)
                self.results.append(result)

                if result.original_severity == result.adjudicated_severity:
                    upheld += 1
                    event_type = EventType.SEVERITY_UPHELD
                    importance = EventImportance.LOW
                    msg = f"Severity upheld for {observation.id}: {result.original_severity}"
                else:
                    adjusted += 1
                    event_type = EventType.SEVERITY_ADJUSTED
                    importance = EventImportance.HIGH
                    msg = (
                        f"Severity adjusted for {observation.id}: "
                        f"{result.original_severity} -> {result.adjudicated_severity}"
                    )

                await self.emit(
                    AgentEvent(
                        event_type=event_type,
                        agent=ComponentType.ADJUDICATOR,
                        importance=importance,
                        message=msg,
                        observation_id=observation.id,
                        details={
                            "original": result.original_severity,
                            "adjudicated": result.adjudicated_severity,
                            "confidence": result.confidence,
                            "approach": result.approach_used,
                        },
                    )
                )
            except Exception as e:
                logger.warning(f"Failed to adjudicate observation {observation.id}: {e}")
                await self.emit(
                    AgentEvent(
                        event_type=EventType.ERROR,
                        agent=ComponentType.ADJUDICATOR,
                        importance=EventImportance.MEDIUM,
                        message=f"Adjudication failed for {observation.id}: {e}",
                        observation_id=observation.id,
                    )
                )

        await self.emit(
            AgentEvent(
                event_type=EventType.ADJUDICATION_COMPLETE,
                agent=ComponentType.ADJUDICATOR,
                importance=EventImportance.MEDIUM,
                message=(
                    f"Adjudication complete: {upheld} upheld, {adjusted} adjusted "
                    f"out of {len(verified)} observations"
                ),
                details={
                    "total": len(verified),
                    "upheld": upheld,
                    "adjusted": adjusted,
                    "approach": AdjudicationApproach.EVIDENCE_RUBRIC,
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
        observation: Observation,
        operator_context: OperatorContext | None,
    ) -> AdjudicatedRisk:
        """Adjudicate a single observation using the evidence rubric."""
        asset_context = self._match_asset_context(observation, operator_context)
        context_str = self._format_context(observation, asset_context)

        response = await self.client.chat(
            prompt=f"Score this observation using the rubric:\n\n{context_str}",
            system=EVIDENCE_RUBRIC_PROMPT,
        )
        return self._parse_rubric_response(observation, response)

    def _match_asset_context(
        self,
        observation: Observation,
        operator_context: OperatorContext | None,
    ) -> OperatorAssetContext | None:
        """Match an observation to operator-declared asset context."""
        if not operator_context or not operator_context.assets:
            return None

        target = observation.target_url or observation.target_service or ""
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
        observation: Observation,
        asset_context: OperatorAssetContext | None,
    ) -> str:
        """Format observation + asset context into a prompt string.

        Uses structured JSON blocks to prevent prompt injection from
        observation data (titles, descriptions, evidence) being
        interpreted as instructions.
        """
        obs_data = {
            "observation_id": observation.id,
            "title": observation.title,
            "description": observation.description,
            "current_severity": str(observation.severity),
            "confidence": observation.confidence,
            "target": observation.target_url or observation.target_service or "unknown",
        }
        if observation.evidence_summary:
            obs_data["evidence"] = observation.evidence_summary
        if observation.exploitation_techniques:
            obs_data["exploitation_techniques"] = observation.exploitation_techniques

        parts = [
            "Observation data:",
            f"```json\n{json.dumps(obs_data, indent=2)}\n```",
        ]

        if asset_context:
            parts.append("")
            parts.append("OPERATOR CONTEXT:")
            parts.append(f"  Asset Exposure: {asset_context.exposure}")
            parts.append(f"  Asset Criticality: {asset_context.criticality}")
            if asset_context.notes:
                parts.append(f"  Notes: {asset_context.notes}")

        return "\n".join(parts)

    def _parse_rubric_response(
        self,
        observation: Observation,
        response: LLMResponse,
    ) -> AdjudicatedRisk:
        """Parse an evidence rubric response with scores."""
        if not response.success:
            logger.warning(f"LLM call failed for {observation.id}: {response.error}")
            return self._fallback_result(observation, response.error or "LLM call failed")

        try:
            data = json.loads(self._clean_json(response.content))
        except (json.JSONDecodeError, ValueError):
            logger.warning(f"Failed to parse rubric JSON for {observation.id}")
            return self._fallback_result(observation, "Failed to parse rubric response")

        scores = data.get("scores", {})
        severity_str = data.get("final_severity", observation.severity).lower()
        try:
            adjudicated_severity = ObservationSeverity(severity_str)
        except ValueError:
            adjudicated_severity = observation.severity

        return AdjudicatedRisk(
            observation_id=observation.id,
            original_severity=observation.severity,
            adjudicated_severity=adjudicated_severity,
            confidence=float(data.get("confidence", 0.5)),
            approach_used=AdjudicationApproach.EVIDENCE_RUBRIC,
            rationale=data.get("rationale", ""),
            factors=scores,
        )

    @staticmethod
    def _fallback_result(observation: Observation, reason: str) -> AdjudicatedRisk:
        """Return a fallback result that upholds the original severity."""
        return AdjudicatedRisk(
            observation_id=observation.id,
            original_severity=observation.severity,
            adjudicated_severity=observation.severity,
            confidence=0.0,
            approach_used=AdjudicationApproach.EVIDENCE_RUBRIC,
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
