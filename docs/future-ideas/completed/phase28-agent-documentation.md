# Phase 28 — Internal Component & Pipeline Documentation

## Problem

Chainsmith has a growing set of internal pipeline components — agents, gates,
and advisors — but no documentation that explains what they are, how they work,
or how they connect. The existing docs cover check suites, CLI usage, scenarios,
and persistence, but an operator or contributor looking to understand the
pipeline has to read source code.

This is distinct from `docs/checks/agent.md`, which documents the agent
*check suite* (security tests run against external AI agents).

## What to document

### 1. Component taxonomy

Document the three component types and their defining traits. See
[component-taxonomy.md](component-taxonomy.md) for the canonical reference.

| Type | Defining trait | Examples |
|------|---------------|----------|
| **Agent** | LLM-powered, autonomous reasoning | Verifier, Adjudicator, Triage, Chainsmith |
| **Gate** | Deterministic policy enforcement | Guardian |
| **Advisor** | Deterministic post-hoc analysis | ScanAdvisor |

**Agents think. Gates block. Advisors suggest.**

### 2. Component reference

A single doc (e.g., `docs/pipeline.md`) covering each component, organized
by type:

#### Gates

##### Guardian (`app/guardian.py`)
- **Role:** Scope enforcement — validates URLs and techniques against the
  operator-defined scope before any check executes. Also enforces engagement
  window restrictions.
- **Type:** Gate (deterministic, no LLM).
- **Consumes:** URLs, techniques, scope definition.
- **Produces:** Approve/reject decisions with violation reasons.
- **When it runs:** Continuously during scanning; every request is checked.

#### Agents

##### VerifierAgent (`app/agents/verifier.py`)
- **Role:** Validates observations, catches hallucinations, assigns confidence
  scores.
- **Type:** Agent (LLM-backed, tool-use loop: verify_cve, verify_version,
  verify_endpoint, submit_verdict).
- **Consumes:** Pending observations.
- **Produces:** Verified/rejected/hallucination verdicts with confidence.
- **When it runs:** After scanning, before chain analysis.

##### AdjudicatorAgent (`app/agents/adjudicator.py`)
- **Role:** Challenges severity ratings using a CVSS-like evidence rubric
  with operator asset context.
- **Type:** Agent (LLM-backed, single structured call per observation).
- **Consumes:** Verified observations + optional operator asset context.
- **Produces:** AdjudicatedRisk (original vs. adjudicated severity,
  confidence, rationale, factors).
- **When it runs:** After verification, before triage.

##### TriageAgent (`app/agents/triage.py`)
- **Role:** Produces prioritized remediation action plan with effort/impact
  matrix, workstream grouping, and team context awareness.
- **Type:** Agent (LLM-backed, single structured call).
- **Consumes:** Verified observations, adjudicated risks, attack chains,
  team context.
- **Produces:** TriagePlan with prioritized actions and workstreams.
- **When it runs:** After adjudication, final pipeline stage.

##### ChainsmithAgent (`app/agents/chainsmith.py`)
- **Role:** Validates chain integrity for custom checks and user-defined
  attack chains. Also handles interactive scoping conversations.
- **Type:** Agent (hybrid — conversational scoping + chain validation).
- **Consumes:** User messages (scoping) or check/chain definitions
  (validation).
- **Produces:** Scope definitions or validation results.
- **When it runs:** Scoping at session start; chain validation on demand.

#### Advisors

##### ScanAdvisor (`app/scan_advisor.py`)
- **Role:** Post-scan analysis — identifies gaps, partial results, follow-up
  opportunities, and coverage shortfalls.
- **Type:** Advisor (deterministic, rule-based, 39+ follow-up triggers).
- **Consumes:** Completed scan state.
- **Produces:** Recommendations (gap analysis, coverage cross-reference,
  follow-up suggestions).
- **When it runs:** After scan completion (optional, disabled by default).

### 3. Pipeline flow diagram

Show the end-to-end flow with component types labeled:

```
Scoping (ChainsmithAgent) ◄── AGENT
    │
    ▼
Guardian (scope enforcement) ◄── GATE
    │
    ▼
Scanning (check suites execute)
    │
    ▼
Verification (VerifierAgent) ◄── AGENT
    │
    ▼
Chain Analysis (pattern engine + LLM discovery)
    │
    ▼
Adjudication (AdjudicatorAgent) ◄── AGENT
    │
    ▼
Triage (TriageAgent) ◄── AGENT
    │
    ▼
ScanAdvisor (post-scan recommendations) ◄── ADVISOR
    │
    ▼
Reporting
```

### 4. Event system

Document the `AgentEvent` model and event types each component emits
(AGENT_START, TOOL_CALL, OBSERVATION_VERIFIED, HALLUCINATION_CAUGHT,
ADJUDICATION_START, SEVERITY_UPHELD, SEVERITY_ADJUSTED, TRIAGE_START,
TRIAGE_ACTION, SCOPE_VIOLATION, etc.) so operators and contributors
understand the live feed.

### 5. Component type distinction

Clearly document which components are which type:

- **Agents** (LLM-backed): Verifier, Adjudicator, Triage, Chainsmith
- **Gates** (deterministic enforcement): Guardian
- **Advisors** (deterministic analysis): ScanAdvisor

This matters for:
- Cost expectations (agents incur LLM costs; gates and advisors do not)
- Reproducibility (gates and advisors are deterministic; agents are not)
- Offline/airgapped operation (gates and advisors work without LLM access)
- Model selection (`--profile` and per-agent model overrides)
- Trust model (gates are trusted implicitly; agent outputs carry uncertainty)

### 6. Configuration surface

For each component, document the relevant configuration:
- Guardian: scope definition structure
- ScanAdvisor: enable/disable, trigger conditions
- Verifier: model override (`model_verifier`)
- Adjudicator: approach selection, operator context file, cost tiering
- Triage: team context file, remediation KB
- Chainsmith: model override (`model_chainsmith`)

## Where it lives

`docs/pipeline.md` — a single reference doc linked from `docs/index.md`
under a new "Architecture" or "Pipeline" section. Avoids scattering component
descriptions across multiple files.

## Relationship to other docs

- `docs/checks/agent.md` — unrelated; documents the agent check suite
  (external-facing security tests)
- `docs/swarm-architecture.md` — covers distributed execution, not the
  internal pipeline
- `docs/OPERATING_MODES.md` — covers scan modes, could cross-reference
  pipeline doc for deeper detail
- [component-taxonomy.md](component-taxonomy.md) — canonical taxonomy
  reference; this doc should align with it
- Phase 26 (model review) — proposes the `ComponentType` enum refactor
  that aligns the code with this taxonomy

## Open questions

- Should each component get its own doc page, or is a single pipeline doc
  sufficient? A single doc keeps the overview coherent, but individual
  pages allow deeper detail per component.
- Should the doc include worked examples showing how an observation flows
  through the entire pipeline (pending -> verified -> adjudicated -> chained
  -> triaged)?
- How much internal implementation detail is appropriate? The doc should
  serve operators understanding what the system does, but also contributors
  who need to modify or extend components.

## Dependencies

- None hard — this is a documentation-only phase.
- Best done after Phase 26 (model review) lands, so naming and type
  changes are settled.
- Should reference [component-taxonomy.md](component-taxonomy.md) as the
  authoritative classification.
