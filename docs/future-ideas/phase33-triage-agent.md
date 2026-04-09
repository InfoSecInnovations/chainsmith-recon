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
Checks -> Verifier -> Adjudicator -> Chainsmith -> Triage Agent
                                                        |
                                                Prioritized Action Plan
```

The Triage Agent is the **final stage** before operator-facing output.
It reads but never modifies upstream data.


---


## Team Capabilities Assessment (Litmus Tests)

### Rationale

Triage prioritization without operator constraints is just severity sorting
with extra LLM cost. But capturing constraints well is hard: team capacity
is fluid, skill matters, constraint types are diverse, and too many fields
means nobody fills them out.

Instead of a detailed profile form, the Triage Agent asks **5 litmus-test
questions** on first invocation. Each question is a concrete scenario that
reveals underlying constraints through the operator's answer — no abstract
self-assessment required. Each answer creates a meaningful fork in how the
triage plan gets ordered.

### First-invocation flow

On the first triage run (no saved team context found), the agent:

1. Introduces itself: what it does, what the action plan will contain.
2. Presents the capability assessment as **optional**:
   > "To make targeted recommendations, I can account for your
   > organization's and team's capabilities. This is optional — you can
   > skip and get a general action plan. Responses are stored locally
   > on this machine and are not uploaded anywhere."
3. Presents the 5 questions (operator can answer or skip any/all).
4. Persists answers to `~/.chainsmith/triage_context.yaml`.
5. Generates the triage plan, informed by answers if provided.

If the operator skips entirely, the triage plan is generated with a
visible caveat:

> "These priorities assume general team capabilities. To get
> recommendations tailored to your team's constraints, run
> `chainsmith triage --configure` or answer the capability questions
> on next invocation."

### Subsequent-invocation flow

When saved team context exists, the agent shows a brief summary:

```
Your saved team context:
  - Deploy to prod this week: Yes
  - Rotate compromised creds in 24h: No (vendor-managed)
  - Team modifies: Application code only
  - People working fixes: 2
  - Off-limits: Auth service (mid-migration), production DB schema

Still accurate? [Y to proceed / N to update]
```

- **Y**: Proceeds immediately with saved context.
- **N**: Re-presents the questions with current answers pre-filled.
  Operator updates only what changed.

This catches drift without forcing operators to re-answer everything.

### The 5 litmus questions

#### Q1: Deployment velocity

> "Can your team deploy a configuration change to production this week?"
>
> (a) Yes — we deploy regularly
> (b) With approval — change board or release window required
> (c) No — deployments are infrequent or externally managed

**What it reveals:** Change authority and deployment cadence. Determines
whether "quick config fix" is actually quick for this team, or whether
triage should front-load detection/monitoring actions and defer
remediation requiring deploys.

**Triage fork:**
| Answer | Effect on plan |
|--------|---------------|
| (a) Yes | Config-level fixes ranked as quick wins |
| (b) With approval | Config fixes ranked as "plan next" (medium effort due to process) |
| (c) No | Config fixes deprioritized; detection/monitoring actions promoted |

#### Q2: Incident response capability

> "If a credential was compromised right now, could your team rotate
> it within 24 hours?"
>
> (a) Yes — we own our secrets and can rotate independently
> (b) Partially — some credentials we control, others are vendor-managed
> (c) No — credential rotation requires external coordination

**What it reveals:** Infrastructure access, operational independence,
and vendor dependency. Changes what "low effort" means for any
credential-related remediation action.

**Triage fork:**
| Answer | Effect on plan |
|--------|---------------|
| (a) Yes | Credential actions ranked as quick wins (low effort, high impact) |
| (b) Partially | Split: self-managed creds are quick wins; vendor creds are strategic |
| (c) No | Credential actions ranked as strategic/high-effort; compensating controls promoted |

#### Q3: Remediation surface

> "Does your team routinely modify application code, infrastructure
> configs, or both?"
>
> (a) Both — full-stack access
> (b) Application code only
> (c) Infrastructure/config only
> (d) Neither — we report findings to another team

**What it reveals:** The remediation surface the team can actually
touch. Directly filters which actions are feasible for this team vs.
need to be escalated.

**Triage fork:**
| Answer | Effect on plan |
|--------|---------------|
| (a) Both | All action types eligible |
| (b) App code only | Infra actions (WAF, headers, TLS) marked as "escalate" |
| (c) Infra only | Code-level fixes (auth logic, input validation) marked as "escalate" |
| (d) Neither | All actions framed as recommendations to forward; effort estimates reflect coordination overhead |

#### Q4: Parallelism capacity

> "How many people will be working on remediations from this report?"
>
> (a) 1 person
> (b) 2-3 people
> (c) 4+ people

**What it reveals:** Whether the team can tackle independent
workstreams simultaneously. Changes plan structure from strict
serial ordering to parallel tracks.

**Triage fork:**
| Answer | Effect on plan |
|--------|---------------|
| (a) 1 person | Strict serial priority list; every action competes |
| (b) 2-3 people | 2-3 parallel tracks grouped by domain/skill |
| (c) 4+ people | Multiple parallel tracks; batch related actions into workstreams |

#### Q5: Current constraints (free-text)

> "Is there anything off-limits for changes right now? (e.g., change
> freezes, services owned by other teams, compliance holds, ongoing
> migrations)"
>
> Free-text response, or "none" to skip.

**What it reveals:** Political, organizational, and temporal blockers
that no structured question can anticipate. This is the escape valve
for constraints the other 4 questions miss.

**Triage fork:** Actions targeting off-limits areas are either excluded
from the plan or explicitly marked as blocked with the stated reason.

### Storage

Team context is persisted to `~/.chainsmith/triage_context.yaml`:

```yaml
# Chainsmith Triage — Team Capabilities
# Stored locally. Not uploaded anywhere.
# Edit directly or run: chainsmith triage --configure

answered_at: "2026-04-09T14:30:00Z"

deployment_velocity: "yes"           # yes | with_approval | no
incident_response: "partially"       # yes | partially | no
remediation_surface: "app_only"      # both | app_only | infra_only | neither
team_size: "2_to_3"                  # solo | 2_to_3 | 4_plus
off_limits: "Auth service (mid-migration), production DB schema changes"
```

The file is human-readable and directly editable. The `answered_at`
timestamp lets the "still accurate?" prompt include how long ago the
answers were captured.

### Loading

A `load_team_context()` function (parallel to the existing
`load_operator_context()` in `app/engine/adjudication.py`) reads and
validates the YAML file, returning `TeamContext | None`.

```python
def load_team_context(
    config: ChainsmithConfig | None = None,
) -> TeamContext | None:
    """Load from ~/.chainsmith/triage_context.yaml. Returns None if missing."""
```

Graceful degradation: missing file, parse errors, or partial answers
all result in `None` or a partially-populated context — never a crash.


---


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
  "category": "credential_management",
  "feasibility": "direct"        // direct | escalate | blocked
}
```

The `feasibility` field is driven by team context:
- `direct` — team can execute this action themselves
- `escalate` — action requires capabilities the team doesn't have (per Q3)
- `blocked` — action targets an off-limits area (per Q5)

### Caveat on uncalibrated plans

When no team context is available, the plan includes a top-level flag:

```
{
  "team_context_available": false,
  "caveat": "These priorities assume general team capabilities.
             Effort estimates and feasibility classifications may not
             reflect your team's actual constraints. Run capability
             assessment for tailored recommendations."
}
```

This caveat appears in both the API response and the UI rendering.

### Triage Factors

The agent weighs these inputs when ordering actions:

| Factor | Source | Weight Rationale |
|--------|--------|-----------------|
| Adjudicated severity | AdjudicatorAgent | Base priority signal |
| Chain membership | ChainsmithAgent | Fixing one link may neutralize entire chains |
| Chain position | attack_patterns.json | Entry-point findings are higher-leverage fixes |
| Exploitability score | AdjudicatedRisk.factors | Practically exploitable > theoretically severe |
| Remediation effort | LLM estimate + team context | Low-effort, high-impact fixes should go first |
| Asset criticality | OperatorAssetContext | Production > staging > dev |
| Observation count | Aggregation | Actions that resolve multiple findings rank higher |
| Deployment velocity | TeamContext Q1 | Can the team actually ship this fix? |
| Remediation surface | TeamContext Q3 | Can the team touch this layer? |
| Team size | TeamContext Q4 | Parallel tracks vs. serial |
| Off-limits areas | TeamContext Q5 | Hard exclusions |

### Effort/Impact Matrix

The agent classifies each action into a 2x2 matrix:

```
                    High Impact
                   +---------------+
        Low Effort |  DO FIRST     |  <- Quick wins
                   +---------------+
       High Effort |  PLAN NEXT    |  <- Strategic fixes
                   +---------------+
                    Low Impact
                   +---------------+
        Low Effort |  BATCH LATER  |  <- Housekeeping
                   +---------------+
       High Effort |  DEPRIORITIZE |  <- Not worth it now
                   +---------------+
```

When team context is available, effort estimates are calibrated to the
team's actual capabilities (e.g., a WAF change is "low effort" for a
team with infra access, "high effort" for an app-only team that must
escalate).

### Parallel tracks (team size > 1)

When Q4 indicates multiple people, the plan includes workstream
groupings:

```
{
  "workstreams": [
    {
      "name": "Credential rotation",
      "assignable_to": 1,
      "actions": [1, 3, 7]        // priority numbers
    },
    {
      "name": "Header hardening",
      "assignable_to": 1,
      "actions": [2, 5, 9]
    }
  ]
}
```

For solo operators (Q4 = 1 person), workstreams are omitted and the
plan is a strict serial list.


---


## Implementation

### Agent Class

```python
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

    async def triage(
        self,
        observations: list[Observation],
        chains: list[AttackChain],
        adjudications: list[AdjudicatedRisk],
        operator_context: OperatorContext | None = None,
        team_context: TeamContext | None = None,
    ) -> TriagePlan:
        ...

    async def emit(self, event: AgentEvent):
        if self.event_callback:
            await self.event_callback(event)

    def stop(self):
        self.is_running = False
```

### Single LLM Call Design

Following the Adjudicator's proven pattern (one structured LLM call,
not multi-turn debate), the Triage Agent makes a single call with:

- All verified observations (with adjudicated risk annotations)
- All attack chains (with severity multipliers)
- Operator asset context (if provided)
- Team capabilities context (if provided)
- Static remediation KB entries matching the observations
- Structured output schema enforcing the action plan format

This keeps cost predictable and output deterministic.

### New Models

```python
class TeamContext(BaseModel):
    """Team capabilities loaded from ~/.chainsmith/triage_context.yaml."""

    deployment_velocity: str | None = None   # yes | with_approval | no
    incident_response: str | None = None     # yes | partially | no
    remediation_surface: str | None = None   # both | app_only | infra_only | neither
    team_size: str | None = None             # solo | 2_to_3 | 4_plus
    off_limits: str | None = None            # free-text or None
    answered_at: datetime | None = None


class ActionFeasibility(StrEnum):
    DIRECT = "direct"       # team can do this
    ESCALATE = "escalate"   # requires capabilities team lacks
    BLOCKED = "blocked"     # targets off-limits area


class TriageAction(BaseModel):
    """A single prioritized remediation action."""
    priority: int
    action: str
    targets: list[str]                    # observation IDs
    chains_neutralized: list[str]         # chain IDs
    reasoning: str
    effort_estimate: Literal["low", "medium", "high"]
    impact_estimate: Literal["low", "medium", "high"]
    feasibility: ActionFeasibility
    remediation_guidance: list[str]
    observations_resolved: list[str]
    category: str


class TriagePlan(BaseModel):
    """Complete prioritized remediation plan."""
    scan_id: str
    generated_at: datetime
    actions: list[TriageAction]
    summary: str                          # 2-3 sentence executive summary
    team_context_available: bool
    caveat: str | None = None             # set when no team context
    quick_wins: int                       # count of low-effort/high-impact
    strategic_fixes: int                  # count of high-effort/high-impact
    workstreams: list[dict] | None = None # parallel tracks if team > 1
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

### Engine Orchestration

```python
# app/engine/triage.py

async def run_triage(state: AppState) -> None:
    """
    Run triage on adjudicated observations and attack chains.

    - Reads observations + adjudications + chains from DB
    - Loads operator context and team context from YAML files
    - Creates TriageAgent and calls triage()
    - Persists TriagePlan to DB
    - Updates scan status: triage_status field
    """
```

Follows the same pattern as `run_adjudication()`:
1. Load inputs from DB
2. Load contexts from YAML (graceful None on missing)
3. Create agent with LLM client
4. Call agent, get results
5. Persist results (fire-and-forget, graceful degradation)
6. Update scan status


---


## Static Remediation KB

### Design: two-layer guidance

1. **Static knowledge base** (`app/data/remediation_guidance.json`):
   Well-known, repeatable fixes keyed by check ID and observation type.
   Deterministic, low-cost, consistent across runs.

2. **LLM contextual layer**: Situational guidance that connects multiple
   findings, adapts to team constraints, and explains *why* a specific
   fix order matters. References static KB entries but adds reasoning.

The static KB keeps token costs down and ensures baseline advice doesn't
drift between model versions. The LLM adds the judgment layer.

### KB entry schema

```json
{
  "check_id": "mcp_exposed_credentials",
  "observation_type": "exposed_credentials",
  "category": "credential_management",
  "title": "Rotate exposed credentials",
  "steps": [
    "Regenerate the token via the admin console.",
    "Update all client configurations referencing the old token.",
    "Verify the old token returns 401."
  ],
  "effort_estimate": "low",
  "requires_infra_access": false,
  "requires_code_change": false,
  "requires_deploy": true,
  "last_verified": "2026-04-01",
  "references": ["OWASP API3", "CWE-798"]
}
```

The `requires_infra_access`, `requires_code_change`, and
`requires_deploy` flags enable the agent to cross-reference team
context (Q1, Q3) when determining feasibility without LLM inference.


---


## UI Integration

The Triage Plan is a natural fit for a dedicated panel in the UI:

- Ordered action list with expand/collapse for remediation guidance
- Effort/impact matrix visualization
- Feasibility badges (direct / escalate / blocked)
- Workstream view for multi-person teams
- Caveat banner when team context is not configured
- Filter by category, effort level, feasibility, or affected chain
- Re-triage button (re-run with updated team context)


---


## Persistence

### Database tables

Triage plans are persisted alongside scans. Operators may need to justify
why remediation followed a specific sequence (audit trail, compliance,
post-incident review). A triage plan is a decision record, not a
transient view.

```sql
CREATE TABLE triage_plans (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    summary TEXT,
    team_context_available INTEGER DEFAULT 0,
    caveat TEXT,
    quick_wins INTEGER DEFAULT 0,
    strategic_fixes INTEGER DEFAULT 0,
    workstreams TEXT,                    -- JSON
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE triage_actions (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    priority INTEGER NOT NULL,
    action TEXT NOT NULL,
    targets TEXT,                        -- JSON array of observation IDs
    chains_neutralized TEXT,             -- JSON array of chain IDs
    reasoning TEXT,
    effort_estimate TEXT,
    impact_estimate TEXT,
    feasibility TEXT,                    -- direct | escalate | blocked
    remediation_guidance TEXT,           -- JSON array of steps
    observations_resolved TEXT,          -- JSON array of observation IDs
    category TEXT,
    FOREIGN KEY (plan_id) REFERENCES triage_plans(id)
);
```

### Scan status extension

Add to the `scans` table:

```
triage_status TEXT DEFAULT 'idle'       -- idle | triaging | complete | error
triage_error TEXT
```


---


## Re-triage

### Tracking completed actions via scan diff

When re-triaging (after a re-scan), the agent compares the current
scan's observations against the prior plan's `observations_resolved`
list. If an observation from the prior plan no longer appears (or its
status changed), the corresponding action is marked completed
automatically. The scan data is the source of truth.

The re-triage output includes a progress section:

```
{
  "prior_plan_id": "tp-abc123",
  "actions_completed": 3,
  "actions_remaining": 5,
  "new_actions": 2,
  "chains_neutralized": 1
}
```

### Partial fixes trigger re-adjudication

When re-triage detects an observation still present but at reduced
severity, it should be sent back through the Adjudicator before Triage
re-prioritizes. Capped at depth 3 per observation with coaching:

- **Depth 1-2**: Normal re-adjudication.
- **Depth 3**: Agent emits coaching guidance explaining repeated partial
  fixes suggest the root cause isn't being addressed. Recommends a
  definitive fix or formal risk acceptance.
- **Beyond 3**: Retains depth-3 score, surfaces coaching again.

### Triage plan diffs across runs

New plans include a `changes_from_prior` section:

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


---


## Design Decisions

### 1. Persist plans in DB — yes

Triage plans are decision records. Operators may need to justify
remediation sequencing for compliance, audit, or post-incident review.

### 2. Hybrid remediation guidance — static KB + LLM

Static KB for deterministic baseline. LLM for situational judgment.
KB entries carry `last_verified` timestamp; LLM flags entries older
than 6 months.

### 3. Consolidation over conflict detection

The agent proactively consolidates actions that address multiple
observations into single remediation steps. An action resolving 4
observations in one step naturally ranks higher in the effort/impact
matrix. Conflict detection is secondary — consolidation-first
minimizes conflicts.

### 4. Risk acceptance is an Adjudicator concern

When an operator accepts a risk via observation overrides, the
Adjudicator reflects that in scoring. Triage simply respects whatever
the Adjudicator decided — no special handling needed.

### 5. Litmus tests over detailed profiles

5 concrete scenario-based questions reveal constraints without
requiring operators to self-assess abstractly. Multiple-choice for
Q1-Q4 keeps capture fast; free-text Q5 catches edge cases.

### 6. Caveat over refusal

When team context is missing, the agent still produces a useful plan
rather than refusing to run. The caveat makes the limitation visible
without blocking the operator.


---


## What This Is NOT

- **Not a replacement for the Adjudicator.** The Adjudicator scores risk
  accuracy. The Triage Agent assumes those scores are correct and optimizes
  *fix order*.
- **Not a report generator.** Reports present findings. The Triage Agent
  presents *actions*. A report says "you have 12 highs." The Triage Agent
  says "fix these 3 things and you neutralize 8 of them."
- **Not an automated remediation system.** It produces guidance, not
  patches. Operators execute the plan.


---


## Dependencies

- Adjudicator Agent — for adjudicated risk scores
- Attack chains — for chain-aware prioritization
- OperatorContext models — for asset exposure and criticality
- Existing agent pattern (event_callback, LLMClient, structured output)


---


## Config

```python
@dataclass
class TriageConfig:
    enabled: bool = True
    context_file: str = "~/.chainsmith/triage_context.yaml"
    kb_path: str = "app/data/remediation_guidance.json"
```

Add `model_triage` to `LiteLLMConfig` (recommend same model as
adjudicator: `nova-pro`).


---


## Implementation Order

| Wave | Scope | Rationale |
|------|-------|-----------|
| 1 | TeamContext model, YAML load/save, litmus questions, "still accurate?" flow | Foundation — data capture before agent logic |
| 2 | TriageAgent class, single LLM call, TriagePlan/TriageAction models, basic prioritization | Core agent — produces action plans |
| 3 | Static remediation KB (initial entries for high-frequency checks), KB integration into prompt | Grounds guidance in deterministic advice |
| 4 | DB persistence (triage_plans, triage_actions tables), scan status extension | Durability and audit trail |
| 5 | Engine orchestration (run_triage), wiring into scan pipeline | End-to-end integration |
| 6 | UI panel (action list, effort/impact matrix, feasibility badges, caveat banner) | Operator-facing output |
| 7 | Re-triage (scan diff, plan diffs, re-adjudication loop) | Iterative remediation tracking |


---


## Open Questions

1. Should the coaching message at re-adjudication depth 3 be
   configurable, or is a single firm default sufficient?
2. Who maintains the remediation KB — is it a community-contributed
   catalog (like check definitions) or a curated internal resource?
3. Should the "still accurate?" check include the age of the saved
   answers (e.g., "saved 3 weeks ago") to nudge updates?
4. Should there be a `chainsmith triage --configure` CLI command to
   re-trigger the litmus questions outside of a triage run?
5. For the free-text Q5, should the agent attempt to parse specific
   service/system names and match them against observation targets, or
   pass the raw text to the LLM and let it interpret?
