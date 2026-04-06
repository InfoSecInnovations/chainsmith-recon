# Phase 28 — Internal Agent & Pipeline Documentation

## Problem

Chainsmith has five internal pipeline components — ScanAdvisor, Verifier,
Chainsmith agent, Adjudicator, and Guardian — but no documentation that
explains what they are, how they work, or how they connect. The existing
docs cover check suites, CLI usage, scenarios, and persistence, but an
operator or contributor looking to understand the pipeline has to read
source code.

This is distinct from `docs/checks/agent.md`, which documents the agent
*check suite* (security tests run against external AI agents).

## What to document

### 1. Agent/component reference

A single doc (e.g., `docs/agents.md` or `docs/pipeline.md`) covering each
component:

#### Guardian (`app/guardian.py`)
- **Role:** Scope enforcement — validates URLs and techniques against the
  operator-defined scope before any check executes.
- **Type:** Deterministic (no LLM).
- **Consumes:** URLs, techniques, scope definition.
- **Produces:** Approve/reject decisions with violation reasons.
- **When it runs:** Continuously during scanning; every request is checked.

#### ScanAdvisor (`app/scan_advisor.py`)
- **Role:** Post-scan advisor — analyzes what ran, what failed, and what
  was found, then recommends follow-up actions.
- **Type:** Deterministic (rule-based, 39+ follow-up triggers).
- **Consumes:** Completed scan state.
- **Produces:** Recommendations (gap analysis, coverage cross-reference,
  follow-up suggestions).
- **When it runs:** After scan completion (optional, disabled by default).

#### VerifierAgent (`app/agents/verifier.py`)
- **Role:** Validates findings, catches hallucinations, assigns confidence
  scores.
- **Type:** LLM-backed (tool-use loop: verify_cve, verify_version,
  verify_endpoint, submit_verdict).
- **Consumes:** Pending findings.
- **Produces:** Verified/rejected/hallucination verdicts with confidence.
- **When it runs:** After scanning, before chain analysis.

#### AdjudicatorAgent (`app/agents/adjudicator.py`)
- **Role:** Challenges and debates severity ratings using adversarial
  reasoning.
- **Type:** LLM-backed (4 approaches: structured_challenge,
  adversarial_debate, evidence_rubric, auto).
- **Consumes:** Verified findings + optional operator asset context.
- **Produces:** AdjudicatedRisk (original vs. adjudicated severity,
  confidence, rationale, CVSS-like factors).
- **When it runs:** After verification, before or after chain analysis.

#### ChainsmithAgent (`app/agents/chainsmith.py`)
- **Role:** Two responsibilities — interactive scoping conversations and
  building attack chains from verified findings.
- **Type:** Hybrid (conversational for scoping, pattern-based for chain
  building using keyword matching against 40+ security concepts).
- **Consumes:** User messages (scoping) or verified findings (chains).
- **Produces:** Scope definitions or attack chains with impact statements.
- **When it runs:** Scoping at session start; chain building after
  verification.

### 2. Pipeline flow diagram

Show the end-to-end flow:

```
Scoping (ChainsmithAgent)
    │
    ▼
Guardian (scope enforcement, continuous)
    │
    ▼
Scanning (check suites execute)
    │
    ▼
ScanAdvisor (optional post-scan recommendations)
    │
    ▼
Verification (VerifierAgent)
    │
    ▼
Adjudication (AdjudicatorAgent, optional)
    │
    ▼
Chain Analysis (ChainsmithAgent + pattern engine)
    │
    ▼
Reporting
```

### 3. Event system

Document the `AgentEvent` model and event types each component emits
(AGENT_START, TOOL_CALL, FINDING_VERIFIED, HALLUCINATION_CAUGHT,
ADJUDICATION_START, SEVERITY_UPHELD, SEVERITY_ADJUSTED, etc.) so
operators and contributors understand the live feed.

### 4. LLM vs. deterministic distinction

Clearly mark which components use LLM calls (Verifier, Adjudicator,
ChainsmithAgent for scoping) vs. which are purely rule-based (Guardian,
ScanAdvisor, chain pattern matching). This matters for:
- Cost expectations
- Reproducibility
- Offline/airgapped operation
- Model selection (`--profile` and per-agent model overrides)

### 5. Configuration surface

For each component, document the relevant configuration:
- Guardian: scope definition structure
- ScanAdvisor: enable/disable, trigger conditions
- Verifier: model override (`model_verifier`)
- Adjudicator: approach selection, operator context file, cost tiering
- ChainsmithAgent: model override (`model_chainsmith`)

## Where it lives

`docs/pipeline.md` — a single reference doc linked from `docs/index.md`
under a new "Architecture" or "Pipeline" section. Avoids scattering agent
descriptions across multiple files.

## Relationship to other docs

- `docs/checks/agent.md` — unrelated; documents the agent check suite
  (external-facing security tests)
- `docs/swarm-architecture.md` — covers distributed execution, not the
  agent pipeline
- `docs/OPERATING_MODES.md` — covers scan modes, could cross-reference
  pipeline doc for deeper detail
- Phase 26 (model review) — proposes renaming `AgentType` to
  `ComponentType`; the new doc should use whatever naming lands there

## Open questions

- Should each agent get its own doc page, or is a single pipeline doc
  sufficient? A single doc keeps the overview coherent, but individual
  pages allow deeper detail per component.
- Should the doc include worked examples showing how a finding flows
  through the entire pipeline (pending → verified → adjudicated → chained)?
- How much internal implementation detail is appropriate? The doc should
  serve operators understanding what the system does, but also contributors
  who need to modify or extend agents.

## Dependencies

- None hard — this is a documentation-only phase.
- Best done after Phase 26 (model review) lands, so naming and type
  changes are settled.
