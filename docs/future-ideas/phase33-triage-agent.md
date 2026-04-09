# Phase 33: Triage Agent — Prioritized Remediation Planning

## Overview

An LLM agent that consumes the full pipeline output (verified observations,
adjudicated risk scores, attack chains) and produces an operator-facing
**prioritized action plan**. The current pipeline tells operators *what exists*
and *how severe it is*. The Triage Agent answers the next question:
**"What should I fix first, and how?"**

## Motivation

- Adjudicated severity alone doesn't determine fix order. A high-severity
  finding behind a VPN may be less urgent than a medium-severity one on an
  internet-facing production endpoint.
- Operators currently receive a flat list of findings sorted by severity.
  They must mentally combine severity, exploitability, asset criticality,
  remediation effort, and business context to decide where to start.
- Attack chains create implicit priorities (break one link, neutralize the
  chain) but these aren't surfaced as actionable guidance.
- Different operators have different constraints — a small team with no
  budget for infrastructure changes needs different advice than a team
  mid-sprint with engineering capacity.

## Pipeline Placement

```
Checks → Verifier → Adjudicator → Chainsmith → Triage Agent
                                                      ↓
                                              Prioritized Action Plan
```

The Triage Agent is the **final stage** before operator-facing output.
It reads but never modifies upstream data.

## What the Triage Agent Produces

### Prioritized Action Plan

An ordered list of remediation actions, each containing:

```
{
  "priority": 1,
  "action": "Rotate exposed MCP server credentials",
  "targets": ["obs-abc123", "obs-def456"],
  "chains_neutralized": ["chain-001"],
  "reasoning": "This single action breaks the highest-severity chain
                and addresses two verified critical findings. The fix
                is low-effort (credential rotation) with immediate impact.",
  "effort_estimate": "low",      // low | medium | high
  "impact_estimate": "high",     // low | medium | high
  "remediation_guidance": [
    "Regenerate the MCP server token via the admin console.",
    "Update all client configurations referencing the old token.",
    "Verify the old token returns 401 by re-running check mcp_007."
  ],
  "observations_resolved": ["obs-abc123", "obs-def456"],
  "category": "credential_management"
}
```

### Triage Factors

The agent weighs these inputs when ordering actions:

| Factor | Source | Weight Rationale |
|--------|--------|-----------------|
| Adjudicated severity | AdjudicatorAgent | Base priority signal |
| Chain membership | ChainsmithAgent | Fixing one link may neutralize entire chains |
| Chain position | attack_patterns.json | Entry-point findings are higher-leverage fixes |
| Exploitability score | AdjudicatedRisk.factors | Practically exploitable > theoretically severe |
| Remediation effort | LLM estimate | Low-effort, high-impact fixes should go first |
| Asset criticality | OperatorAssetContext | Production > staging > dev |
| Observation count | Aggregation | Actions that resolve multiple findings rank higher |

### Effort/Impact Matrix

The agent classifies each action into a 2x2 matrix:

```
                    High Impact
                   ┌───────────────┐
        Low Effort │  DO FIRST     │  ← Quick wins
                   ├───────────────┤
       High Effort │  PLAN NEXT    │  ← Strategic fixes
                   └───────────────┘
                    Low Impact
                   ┌───────────────┐
        Low Effort │  BATCH LATER  │  ← Housekeeping
                   ├───────────────┤
       High Effort │  DEPRIORITIZE │  ← Not worth it now
                   └───────────────┘
```

## Operator Context Integration

The Triage Agent accepts optional operator context to refine prioritization:

- **Team capacity**: "We have 2 engineers for 1 week" → bias toward
  low-effort actions, batch the rest.
- **Remediation constraints**: "We cannot change infrastructure this
  quarter" → deprioritize infra-level fixes, surface application-level
  alternatives.
- **Business priorities**: "The payment API is our most critical service"
  → boost priority for findings affecting that service.

This context is provided via the existing `OperatorContext` / 
`OperatorAssetContext` models, extended if needed.

## Implementation

### Agent Class

```python
class TriageAgent:
    """Produces prioritized remediation plans from pipeline output."""

    def __init__(self, event_callback=None):
        self.event_callback = event_callback
        self.client = get_llm_client()

    async def triage(
        self,
        observations: list[Observation],
        chains: list[AttackChain],
        operator_context: OperatorContext | None = None,
    ) -> TriagePlan:
        ...
```

### Single LLM Call Design

Following the Adjudicator's proven pattern (one structured LLM call,
not multi-turn debate), the Triage Agent makes a single call with:

- All verified observations (with adjudicated risk annotations)
- All attack chains (with severity multipliers)
- Operator context (if provided)
- Structured output schema enforcing the action plan format

This keeps cost predictable and output deterministic.

### New Models

```python
class TriageAction(BaseModel):
    """A single prioritized remediation action."""
    priority: int
    action: str
    targets: list[str]                    # observation IDs
    chains_neutralized: list[str]         # chain IDs
    reasoning: str
    effort_estimate: Literal["low", "medium", "high"]
    impact_estimate: Literal["low", "medium", "high"]
    remediation_guidance: list[str]
    observations_resolved: list[str]
    category: str

class TriagePlan(BaseModel):
    """Complete prioritized remediation plan."""
    scan_id: str
    generated_at: datetime
    actions: list[TriageAction]
    summary: str                          # 2-3 sentence executive summary
    operator_context_used: bool
    quick_wins: int                       # count of low-effort/high-impact
    strategic_fixes: int                  # count of high-effort/high-impact
```

### New Event Types

```python
class EventType(StrEnum):
    # ... existing ...
    TRIAGE_START = "triage_start"
    TRIAGE_COMPLETE = "triage_complete"
    TRIAGE_ACTION = "triage_action"       # emitted per action for live UI
```

### New AgentType Entry

```python
class AgentType(StrEnum):
    # ... existing ...
    TRIAGE = "triage"
```

## UI Integration

The Triage Plan is a natural fit for a dedicated panel in the UI:

- Ordered action list with expand/collapse for remediation guidance
- Effort/impact matrix visualization
- "Mark as done" checkboxes that track remediation progress
- Filter by category, effort level, or affected chain
- Re-triage button (re-run with updated operator context)

## What This Is NOT

- **Not a replacement for the Adjudicator.** The Adjudicator scores risk
  accuracy. The Triage Agent assumes those scores are correct and optimizes
  *fix order*.
- **Not a report generator.** Reports present findings. The Triage Agent
  presents *actions*. A report says "you have 12 highs." The Triage Agent
  says "fix these 3 things and you neutralize 8 of them."
- **Not an automated remediation system.** It produces guidance, not
  patches. Operators execute the plan.

## Dependencies

- Adjudicator Agent (Phase 21) — for adjudicated risk scores
- Attack chains — for chain-aware prioritization
- OperatorContext models — for constraint-aware ordering

## Design Decisions

### 1. Persistence — Yes, persist plans in DB

Triage plans are persisted alongside scans. Operators may need to justify
why remediation followed a specific sequence (audit trail, compliance,
post-incident review). A triage plan is a decision record, not a
transient view.

Schema: `triage_plans` table linked to `scan_id`, with a
`triage_actions` child table for individual actions. Each plan stores
the operator context that was active at generation time so the reasoning
is reproducible.

### 2. Re-triage tracks completed actions via scan diff

When re-triaging, the agent compares the current scan's observations
against the prior plan's `observations_resolved` list. If an observation
from the prior plan no longer appears in the current scan (or its status
changed), the corresponding action is marked completed automatically.
The scan data itself is the source of truth — no manual spot-checking
required.

The re-triage output includes a "progress" section:

```
{
  "prior_plan_id": "tp-abc123",
  "actions_completed": 3,
  "actions_remaining": 5,
  "new_actions": 2,          // from newly discovered observations
  "chains_neutralized": 1,
  "completed_actions": ["tp-act-001", "tp-act-003", "tp-act-004"]
}
```

### 3. Hybrid remediation guidance — static KB + LLM

Two-layer approach:

- **Static knowledge base**: Well-known, repeatable fixes (rotate
  credentials, add HSTS header, disable debug endpoints, patch to
  version X). These are deterministic, low-cost, and consistent across
  runs. Stored as a remediation catalog keyed by **both** check ID and
  observation type. Check ID gives precise fix guidance for a specific
  check's output; observation type provides fallback guidance when a
  check-specific entry doesn't exist.
- **LLM contextual layer**: Situational guidance that connects multiple
  findings, adapts to operator constraints, or explains *why* a specific
  fix order matters. The LLM references the static KB entries but adds
  reasoning about interdependencies and operator context.

The static KB keeps token costs down and ensures baseline advice doesn't
drift between model versions. The LLM adds the judgment layer.

### 4. Consolidation over conflict detection — multi-fix actions

Rather than flagging conflicting actions after the fact, the agent should
**proactively consolidate** actions that address multiple observations
into single remediation steps. This is a primary design goal, not an
edge case.

Example: if 4 observations all stem from an exposed admin panel, the
triage plan should produce one action ("Restrict admin panel access to
internal network") that resolves all 4, rather than 4 separate actions
that might conflict.

The `observations_resolved` field on each `TriageAction` already supports
this — an action that resolves 4 observations in one step naturally
ranks higher in the effort/impact matrix (high impact, single effort).

Conflict detection becomes a secondary concern: when consolidation is
done well, conflicting actions are rare. The agent should still flag
genuine conflicts (e.g., "upgrade to v3" vs. "roll back to v1" for the
same service) but the consolidation-first approach minimizes these.

### 5. Partial fixes trigger re-adjudication

When re-triage detects an observation that still exists but at a reduced
severity (e.g., critical → medium after a partial remediation), the
observation should be sent back through the Adjudicator before Triage
re-prioritizes. The Adjudicator re-scores with the new evidence context,
and Triage consumes the updated adjudication.

This creates a feedback loop in the pipeline:

```
Re-scan → Triage detects partial fix
        → Adjudicator re-scores affected observations
        → Triage re-prioritizes with updated scores
```

The re-triage progress section tracks these as `partially_resolved`:

```
{
  "partially_resolved": [
    {
      "action_id": "tp-act-002",
      "observation_id": "obs-xyz789",
      "original_severity": "critical",
      "current_severity": "medium",
      "sent_to_adjudicator": true
    }
  ]
}
```

### 6. Risk acceptance is an Adjudicator concern, not Triage

Operator risk acceptance (via observation overrides) is a severity
judgment: "I acknowledge this finding and accept the risk." This belongs
in the Adjudicator's domain. When an operator accepts a risk, the
Adjudicator should reflect that in its scoring (effectively treating
the observation as operator-acknowledged).

The Triage Agent simply respects whatever the Adjudicator decided. If
the Adjudicator marked an observation as accepted, Triage excludes it
from the action plan — no special handling needed in Triage itself.

This keeps responsibility boundaries clean:
- **Adjudicator** owns all severity/risk judgments (including acceptance)
- **Triage** owns fix ordering and consolidation

### 7. Re-adjudication loop capped at depth 3 with coaching

The re-adjudication loop (partial fix → re-score → re-triage) is capped
at 3 cycles per observation. Beyond 2 you're in diminishing returns.

Behavior at each depth:
- **Depth 1-2**: Normal re-adjudication. No commentary.
- **Depth 3**: Agent allows the re-adjudication but emits coaching
  guidance to the operator explaining that repeated partial fixes to the
  same observation suggest the root cause isn't being addressed. Firmly
  recommends either a definitive fix or explicit risk acceptance.
- **Beyond 3**: Agent still accepts re-triage requests but will not
  re-adjudicate the capped observation. It retains the depth-3 score
  and surfaces the coaching message again.

Tracked per observation:

```
{
  "observation_id": "obs-xyz789",
  "adjudication_depth": 3,
  "depth_coaching_emitted": true,
  "coaching_message": "This observation has been partially remediated
    3 times without full resolution. Consider addressing the root cause
    or formally accepting the residual risk."
}
```

### 8. Remediation KB staleness — best-effort, defensible

Staleness is fundamentally unsolvable (you'd need to track every
upstream vendor's release cycle). The defensible best-effort approach:

- **Version-agnostic by default**: Prefer guidance that doesn't pin
  versions ("upgrade to latest stable", "rotate credentials", "restrict
  network access"). Version-specific entries only when the fix genuinely
  requires a specific version.
- **`last_verified` timestamp** on every KB entry. Operators can see
  guidance age.
- **LLM staleness flag**: When the LLM contextual layer references a KB
  entry older than 6 months, it appends a note: "This guidance was last
  verified on [date] — confirm applicability before acting."
- **No auto-expiry**: Stale guidance is better than no guidance. Entries
  are never automatically removed — they're flagged, not deleted.

This is defensible because the operator is always informed of guidance
age and can make their own judgment call.

### 9. Triage plan diffs across runs

Triage plans are diffable. When re-triage generates a new plan, it
includes a `changes_from_prior` section showing what moved:

```
{
  "prior_plan_id": "tp-abc123",
  "actions_added": [...],
  "actions_removed": [...],
  "actions_reprioritized": [
    {
      "action_id": "tp-act-005",
      "old_priority": 4,
      "new_priority": 1,
      "reason": "Severity upgraded after re-adjudication"
    }
  ],
  "actions_completed": [...]
}
```

This serves as a progress artifact — operators can show stakeholders
how the risk posture evolved across triage cycles.

## Open Questions

1. Should the coaching message at adjudication depth 3 be configurable,
   or is a single firm default sufficient?
2. Who maintains the remediation KB — is it a community-contributed
   catalog (like check definitions) or a curated internal resource?
