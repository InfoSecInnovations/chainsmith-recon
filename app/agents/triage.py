"""
Triage Agent

Consumes pipeline output (verified observations, adjudicated risk scores,
attack chains) and produces a prioritized remediation action plan.

The current pipeline tells operators *what exists* and *how severe it is*.
The Triage Agent answers: "What should I fix first, and how?"

Uses a single LLM call (following the Adjudicator pattern) with structured
output for deterministic, cost-predictable results.
"""

import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from app.lib.llm import LLMClient, LLMResponse
from app.models import (
    ActionFeasibility,
    AdjudicatedRisk,
    AgentEvent,
    AttackChain,
    ComponentType,
    EventImportance,
    EventType,
    Observation,
    OperatorContext,
    TeamContext,
    TriageAction,
    TriagePlan,
)

logger = logging.getLogger(__name__)


# ─── Remediation KB ────────────────────────────────────────────


def load_remediation_kb(kb_path: str | None = None) -> list[dict]:
    """Load the static remediation knowledge base.

    Returns an empty list if the file is missing or unparseable.
    """
    if kb_path is None:
        kb_path = "app/data/remediation_guidance.json"

    path = Path(kb_path)
    if not path.exists():
        logger.info("No remediation KB found at %s", path)
        return []

    try:
        with open(path) as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return data
        logger.warning("Remediation KB is not a JSON array")
        return []
    except Exception as e:
        logger.warning("Failed to load remediation KB: %s", e)
        return []


def _match_kb_entries(
    observations: list[Observation],
    kb: list[dict],
) -> list[dict]:
    """Return KB entries whose check_id or observation_type matches any observation."""
    obs_types = set()
    obs_check_names = set()
    for obs in observations:
        obs_types.add(obs.observation_type.lower())
        obs_check_names.add(obs.observation_type.lower())

    matched = []
    for entry in kb:
        check_id = (entry.get("check_id") or "").lower()
        obs_type = (entry.get("observation_type") or "").lower()
        if check_id in obs_check_names or obs_type in obs_types:
            matched.append(entry)
    return matched


# ─── System Prompt ─────────────────────────────────────────────

TRIAGE_SYSTEM_PROMPT = """\
You are a security remediation triage agent. Given a set of verified \
observations (with adjudicated severity scores) and attack chains, produce \
a prioritized action plan that tells the operator what to fix first and how.

PRIORITIZATION FACTORS (in order of weight):
1. Chain membership: Fixing one link can neutralize entire attack chains.
   Entry-point observations are higher-leverage fixes.
2. Adjudicated severity: Higher severity = higher priority (all else equal).
3. Exploitability: Practically exploitable > theoretically severe.
4. Consolidation: Actions that resolve multiple observations rank higher.
5. Effort/impact ratio: Low-effort, high-impact fixes ("quick wins") first.
6. Asset criticality: Production > staging > dev.

EFFORT/IMPACT MATRIX:
- Low effort + High impact  = DO FIRST (quick wins)
- High effort + High impact = PLAN NEXT (strategic fixes)
- Low effort + Low impact   = BATCH LATER (housekeeping)
- High effort + Low impact  = DEPRIORITIZE

TEAM CONTEXT RULES (when provided):
- deployment_velocity="no": Deprioritize fixes requiring deploys; promote \
  detection/monitoring actions.
- deployment_velocity="with_approval": Config fixes are medium effort.
- incident_response="no": Credential actions are high-effort; promote \
  compensating controls.
- incident_response="partially": Split vendor-managed vs self-managed creds.
- remediation_surface="app_only": Infrastructure actions (WAF, headers, TLS) \
  get feasibility="escalate".
- remediation_surface="infra_only": Code-level fixes get feasibility="escalate".
- remediation_surface="neither": All actions are recommendations to forward; \
  feasibility="escalate".
- off_limits: Actions targeting mentioned areas get feasibility="blocked".

WORKSTREAMS (when team_size is "2_to_3" or "4_plus"):
Group related actions into parallel workstreams by domain/skill.
For "solo" teams, omit workstreams entirely.

Output valid JSON only, no markdown fences:
{
  "summary": "2-3 sentence executive summary",
  "actions": [
    {
      "priority": 1,
      "action": "Short action title",
      "targets": ["obs-id-1", "obs-id-2"],
      "chains_neutralized": ["chain-id-1"],
      "reasoning": "Why this action, why this priority",
      "effort_estimate": "low|medium|high",
      "impact_estimate": "low|medium|high",
      "feasibility": "direct|escalate|blocked",
      "remediation_guidance": ["Step 1", "Step 2", "Step 3"],
      "observations_resolved": ["obs-id-1", "obs-id-2"],
      "category": "credential_management|header_hardening|access_control|..."
    }
  ],
  "workstreams": [
    {
      "name": "Workstream name",
      "assignable_to": 1,
      "actions": [1, 3, 7]
    }
  ]
}

If team_size is "solo" or not provided, set workstreams to null.
"""


# ─── Agent ─────────────────────────────────────────────────────


class TriageAgent:
    """Produces prioritized remediation plans from pipeline output."""

    def __init__(
        self,
        client: LLMClient,
        event_callback: Callable[[AgentEvent], Awaitable[None]] | None = None,
    ):
        self.client = client
        self.event_callback = event_callback
        self.is_running = False

    async def emit(self, event: AgentEvent):
        """Emit event to callback."""
        if self.event_callback:
            await self.event_callback(event)

    async def triage(
        self,
        observations: list[Observation],
        chains: list[AttackChain],
        adjudications: list[AdjudicatedRisk],
        operator_context: OperatorContext | None = None,
        team_context: TeamContext | None = None,
        kb_entries: list[dict] | None = None,
        scan_id: str = "",
    ) -> TriagePlan:
        """
        Produce a prioritized remediation plan.

        Args:
            observations: Verified observations with adjudicated risk.
            chains: Attack chains identified by ChainsmithAgent.
            adjudications: Adjudicated risk results.
            operator_context: Asset exposure/criticality context.
            team_context: Team capabilities from litmus questions.
            kb_entries: Matched remediation KB entries.
            scan_id: Current scan ID for the plan.

        Returns:
            TriagePlan with ordered remediation actions.
        """
        self.is_running = True

        if not observations:
            logger.info("No observations to triage")
            self.is_running = False
            return TriagePlan(
                scan_id=scan_id,
                summary="No observations to triage.",
                team_context_available=team_context is not None,
                caveat="No verified observations found for this scan.",
            )

        await self.emit(
            AgentEvent(
                event_type=EventType.TRIAGE_START,
                agent=ComponentType.TRIAGE,
                importance=EventImportance.MEDIUM,
                message=(
                    f"Triage Agent starting prioritization of "
                    f"{len(observations)} observations, {len(chains)} chains..."
                ),
                details={
                    "total_observations": len(observations),
                    "total_chains": len(chains),
                    "team_context": team_context is not None,
                },
            )
        )

        # Build prompt
        prompt = self._build_prompt(
            observations,
            chains,
            adjudications,
            operator_context,
            team_context,
            kb_entries,
        )

        # Single LLM call
        response = await self.client.chat(
            prompt=prompt,
            system=TRIAGE_SYSTEM_PROMPT,
            max_tokens=4000,
        )

        plan = self._parse_response(response, scan_id, team_context)

        # Emit per-action events
        for action in plan.actions:
            if not self.is_running:
                break
            await self.emit(
                AgentEvent(
                    event_type=EventType.TRIAGE_ACTION,
                    agent=ComponentType.TRIAGE,
                    importance=EventImportance.MEDIUM
                    if action.impact_estimate == "high"
                    else EventImportance.LOW,
                    message=(
                        f"#{action.priority}: {action.action} "
                        f"[{action.effort_estimate} effort / {action.impact_estimate} impact]"
                    ),
                    details={
                        "priority": action.priority,
                        "feasibility": action.feasibility,
                        "category": action.category,
                        "observations_resolved": len(action.observations_resolved),
                    },
                )
            )

        await self.emit(
            AgentEvent(
                event_type=EventType.TRIAGE_COMPLETE,
                agent=ComponentType.TRIAGE,
                importance=EventImportance.MEDIUM,
                message=(
                    f"Triage complete: {len(plan.actions)} actions, "
                    f"{plan.quick_wins} quick wins, "
                    f"{plan.strategic_fixes} strategic fixes"
                ),
                details={
                    "total_actions": len(plan.actions),
                    "quick_wins": plan.quick_wins,
                    "strategic_fixes": plan.strategic_fixes,
                    "team_context_available": plan.team_context_available,
                },
            )
        )

        self.is_running = False
        return plan

    def stop(self):
        """Stop the triage agent."""
        self.is_running = False

    # ─── Internal ────────────────────────────────────────────────

    def _build_prompt(
        self,
        observations: list[Observation],
        chains: list[AttackChain],
        adjudications: list[AdjudicatedRisk],
        operator_context: OperatorContext | None,
        team_context: TeamContext | None,
        kb_entries: list[dict] | None,
    ) -> str:
        """Build the full prompt for the triage LLM call."""
        # Index adjudications by observation ID
        adj_by_obs = {a.observation_id: a for a in adjudications}

        parts: list[str] = []

        # Observations section
        parts.append("=== VERIFIED OBSERVATIONS ===\n")
        for obs in observations:
            adj = adj_by_obs.get(obs.id)
            severity = adj.adjudicated_severity if adj else obs.severity
            confidence = adj.confidence if adj else obs.confidence

            parts.append(f"ID: {obs.id}")
            parts.append(f"  Title: {obs.title}")
            parts.append(f"  Description: {obs.description}")
            parts.append(f"  Severity: {severity}")
            parts.append(f"  Confidence: {confidence}")
            parts.append(f"  Target: {obs.target_url or obs.target_service or 'unknown'}")
            parts.append(f"  Type: {obs.observation_type}")
            if adj and adj.factors:
                exploitability = adj.factors.get("exploitability", "unknown")
                parts.append(f"  Exploitability: {exploitability}")
            if adj and adj.rationale:
                parts.append(f"  Adjudication: {adj.rationale}")
            if obs.evidence_summary:
                parts.append(f"  Evidence: {obs.evidence_summary}")
            parts.append("")

        # Chains section
        if chains:
            parts.append("\n=== ATTACK CHAINS ===\n")
            for chain in chains:
                parts.append(f"Chain ID: {chain.id}")
                parts.append(f"  Title: {chain.title}")
                parts.append(f"  Severity: {chain.combined_severity}")
                parts.append(f"  Observations: {', '.join(chain.observation_ids)}")
                parts.append(f"  Steps: {' -> '.join(chain.attack_steps)}")
                parts.append(f"  Impact: {chain.impact_statement}")
                parts.append("")

        # Operator context
        if operator_context and operator_context.assets:
            parts.append("\n=== OPERATOR CONTEXT ===\n")
            for asset in operator_context.assets:
                parts.append(
                    f"  {asset.domain}: exposure={asset.exposure}, criticality={asset.criticality}"
                )
                if asset.notes:
                    parts.append(f"    Notes: {asset.notes}")
            parts.append("")

        # Team context
        if team_context:
            parts.append("\n=== TEAM CONTEXT ===\n")
            if team_context.deployment_velocity:
                parts.append(f"  Deployment velocity: {team_context.deployment_velocity}")
            if team_context.incident_response:
                parts.append(f"  Incident response: {team_context.incident_response}")
            if team_context.remediation_surface:
                parts.append(f"  Remediation surface: {team_context.remediation_surface}")
            if team_context.team_size:
                parts.append(f"  Team size: {team_context.team_size}")
            if team_context.off_limits:
                parts.append(f"  Off-limits: {team_context.off_limits}")
            parts.append("")

        # KB entries
        if kb_entries:
            parts.append("\n=== REMEDIATION KNOWLEDGE BASE ===\n")
            for entry in kb_entries:
                parts.append(f"Check: {entry.get('check_id', 'unknown')}")
                parts.append(f"  Title: {entry.get('title', '')}")
                steps = entry.get("steps", [])
                if steps:
                    parts.append(f"  Steps: {'; '.join(steps)}")
                parts.append(f"  Effort: {entry.get('effort_estimate', 'unknown')}")
                parts.append(
                    f"  Requires: infra={entry.get('requires_infra_access', False)}, "
                    f"code={entry.get('requires_code_change', False)}, "
                    f"deploy={entry.get('requires_deploy', False)}"
                )
                refs = entry.get("references", [])
                if refs:
                    parts.append(f"  References: {', '.join(refs)}")
                parts.append("")

        parts.append(
            "\nProduce a prioritized action plan based on the above. "
            "Consolidate actions that address multiple observations into single steps."
        )

        return "\n".join(parts)

    def _parse_response(
        self,
        response: LLMResponse,
        scan_id: str,
        team_context: TeamContext | None,
    ) -> TriagePlan:
        """Parse the LLM response into a TriagePlan."""
        tc_available = team_context is not None
        caveat = None
        if not tc_available:
            caveat = (
                "These priorities assume general team capabilities. "
                "Effort estimates and feasibility classifications may not "
                "reflect your team's actual constraints. Run capability "
                "assessment for tailored recommendations."
            )

        if not response.success:
            logger.warning("Triage LLM call failed: %s", response.error)
            return TriagePlan(
                scan_id=scan_id,
                summary=f"Triage failed: {response.error}",
                team_context_available=tc_available,
                caveat=caveat,
            )

        try:
            data = json.loads(_clean_json(response.content))
        except (json.JSONDecodeError, ValueError):
            logger.warning("Failed to parse triage JSON response")
            return TriagePlan(
                scan_id=scan_id,
                summary="Triage produced unparseable output.",
                team_context_available=tc_available,
                caveat=caveat,
            )

        # Parse actions
        actions: list[TriageAction] = []
        for raw in data.get("actions", []):
            try:
                feasibility_str = raw.get("feasibility", "direct")
                try:
                    feasibility = ActionFeasibility(feasibility_str)
                except ValueError:
                    feasibility = ActionFeasibility.DIRECT

                actions.append(
                    TriageAction(
                        priority=int(raw.get("priority", len(actions) + 1)),
                        action=raw.get("action", ""),
                        targets=raw.get("targets", []),
                        chains_neutralized=raw.get("chains_neutralized", []),
                        reasoning=raw.get("reasoning", ""),
                        effort_estimate=raw.get("effort_estimate", "medium"),
                        impact_estimate=raw.get("impact_estimate", "medium"),
                        feasibility=feasibility,
                        remediation_guidance=raw.get("remediation_guidance", []),
                        observations_resolved=raw.get("observations_resolved", []),
                        category=raw.get("category", ""),
                    )
                )
            except Exception as e:
                logger.warning("Failed to parse triage action: %s", e)

        # Count quick wins and strategic fixes
        quick_wins = sum(
            1 for a in actions if a.effort_estimate == "low" and a.impact_estimate == "high"
        )
        strategic_fixes = sum(
            1 for a in actions if a.effort_estimate == "high" and a.impact_estimate == "high"
        )

        # Parse workstreams
        workstreams = data.get("workstreams")

        return TriagePlan(
            scan_id=scan_id,
            actions=actions,
            summary=data.get("summary", ""),
            team_context_available=tc_available,
            caveat=caveat,
            quick_wins=quick_wins,
            strategic_fixes=strategic_fixes,
            workstreams=workstreams,
        )


def _clean_json(text: str) -> str:
    """Strip markdown fences and whitespace from LLM JSON output."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        cleaned = "\n".join(lines)
    return cleaned.strip()
