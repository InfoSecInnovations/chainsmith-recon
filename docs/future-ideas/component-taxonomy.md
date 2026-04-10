# Component Taxonomy

Chainsmith's internal pipeline is built from three distinct component types.
The distinction matters: it tells operators what to trust implicitly, what to
interrogate, and where policy lives.

| Type | Defining trait | Examples |
|------|---------------|----------|
| **Agent** | LLM-powered, autonomous reasoning, may use tools | Verifier, Adjudicator, Triage |
| **Gate** | Deterministic policy enforcement — pass/fail decisions on data flowing through the pipeline | Guardian |
| **Advisor** | Deterministic post-hoc analysis — reads results, produces recommendations, never blocks | ScanAdvisor |

**Agents think. Gates block. Advisors suggest.**

---

## Agents

Agents make LLM calls and may run tool-use loops. Their outputs carry
uncertainty and require audit trails. Each agent emits `AgentEvent` objects
that stream to the operator via SSE.

### Implemented

| Agent | Pipeline stage | What it does |
|-------|---------------|-------------|
| **Verifier** | Post-scan | Validates observations against external evidence. Tool-use loop (verify_cve, verify_version, verify_endpoint). Catches hallucinations. |
| **Adjudicator** | Post-verification | Challenges severity ratings using a CVSS-like evidence rubric with operator asset context. Single structured LLM call per observation. |
| **Triage** | Post-adjudication | Produces prioritized remediation action plan with effort/impact matrix, workstream grouping, and team context awareness. |
| **Chainsmith** | Scoping + chain validation | Conversational scoping flow. Validates chain integrity for custom checks and user-defined attack chains. |

### Proposed

| Agent | Pipeline stage | What it does |
|-------|---------------|-------------|
| **Coach** | On-demand (chat) | Always-available conversational explainer. Answers "what is CORS?" or "why was this rejected?" grounded in session context. No tools — pure LLM reasoning. |
| **Chain Analyst** | Post-chain-detection | Deep iterative reasoning over observation relationships. Goes beyond the single-shot LLM chain discovery pass — examines clusters individually, considers temporal ordering, builds chains with explicit reasoning trails across suites. |

### When to add a new Agent

Add an agent when the task requires:
- LLM reasoning (not just rule evaluation)
- Iterative tool use or multi-turn reasoning
- Outputs that carry uncertainty and need audit trails

If the logic can be expressed as deterministic rules, it's a Gate or Advisor.

---

## Gates

Gates enforce policy. They make binary pass/fail decisions on data flowing
through the pipeline. They never call an LLM. They are trusted implicitly —
if a gate blocks something, the pipeline respects it without appeal.

### Implemented

| Gate | Pipeline stage | What it enforces |
|------|---------------|-----------------|
| **Guardian** | Pre-execution (runtime) | Scope enforcement — validates URLs and techniques against in-scope/out-of-scope domains, forbidden techniques, and engagement window restrictions. Caches decisions. Emits SCOPE_VIOLATION events. |

### Proposed

| Gate | Pipeline stage | What it enforces |
|------|---------------|-----------------|
| **Check Policy Gate** | Pre-execution | Organizational policy on check execution — blocks intrusive checks without explicit approval, enforces required ordering, applies cost/time budgets. |

### When to add a new Gate

Add a gate when:
- A decision is binary (allow/deny) with no ambiguity
- The logic is expressible as deterministic rules
- The pipeline must respect the decision unconditionally
- No LLM reasoning is needed

---

## Advisors

Advisors analyze completed pipeline state and produce recommendations. They
never block pipeline execution. They are informational — the operator or
downstream components decide whether to act on their suggestions.

### Implemented

| Advisor | Pipeline stage | What it analyzes |
|---------|---------------|-----------------|
| **ScanAdvisor** | Post-scan | Gap analysis (checks that couldn't run due to missing context), partial results (checks that errored/timed out), follow-up suggestions (rule-driven), suite coverage thresholds. |

### Proposed

| Advisor | Pipeline stage | What it analyzes |
|---------|---------------|-----------------|
| **Proof Advisor** | Post-verification | Generates templated reproduction steps, copy-pasteable exploit commands, evidence checklists, and severity justification from check metadata and observation evidence. Deterministic — no LLM. |
| **AlmostCompleteChains** | Post-chain-detection | Identifies chain patterns missing a single element. Reports which check would complete the chain and against which target. Directly actionable. |
| **RemediationBundler** | Pre-triage | Collapses related findings into single remediation actions. Groups observations by root cause, target, or fix — e.g., "these 4 missing-header findings are one nginx config change." |
| **Consistency Advisor** | Post-adjudication | Flags divergent severity scores on similar observations. "XSS on api.example.com rated high but same XSS on www.example.com rated medium — intentional?" |
| **Drift Advisor** | Cross-engagement | Compares current scan results against previous engagement on the same target. Reports new findings, resolved findings, and severity changes since last scan. |
| **Cost Advisor** | Post-triage | Estimates total remediation effort against team context. "14 actions across 3 workstreams — at your team's velocity, roughly 2 sprints of work." |

### When to add a new Advisor

Add an advisor when:
- The analysis reads completed state (never modifies it)
- The output is a recommendation, not a decision
- The logic is deterministic (rule-based, heuristic, or templated)
- The pipeline should not block on its output

---

## Pipeline Flow

```
Scope & Config
     │
     ▼
┌─────────┐
│ Guardian │ ◄── GATE: scope enforcement
└────┬────┘
     │
     ▼
Check Execution (CheckLauncher)
     │  ┌──────────────────┐
     │  │ Check Policy Gate │ ◄── GATE: org policy (proposed)
     │  └──────────────────┘
     │
     ▼
┌──────────┐
│ Verifier │ ◄── AGENT: observation validation
└────┬─────┘
     │
     ▼
┌──────────────┐
│ Chainsmith   │ ◄── AGENT: chain validation
│ Chain Engine │     (pattern matching + LLM discovery)
└────┬─────────┘
     │  ┌───────────────────────┐
     │  │ AlmostCompleteChains  │ ◄── ADVISOR: gap identification (proposed)
     │  └───────────────────────┘
     │  ┌────────────────┐
     │  │ Chain Analyst   │ ◄── AGENT: deep chain reasoning (proposed)
     │  └────────────────┘
     │
     ▼
┌──────────────┐
│ Adjudicator  │ ◄── AGENT: severity challenge
└────┬─────────┘
     │  ┌───────────────────────┐
     │  │ Consistency Advisor   │ ◄── ADVISOR: severity divergence (proposed)
     │  └───────────────────────┘
     │
     ▼
┌───────────────────────┐
│ RemediationBundler    │ ◄── ADVISOR: finding consolidation (proposed)
└────┬──────────────────┘
     │
     ▼
┌─────────┐
│ Triage  │ ◄── AGENT: remediation planning
└────┬────┘
     │  ┌────────────────┐
     │  │ Cost Advisor   │ ◄── ADVISOR: effort estimation (proposed)
     │  └────────────────┘
     │
     ▼
┌──────────────┐
│ ScanAdvisor  │ ◄── ADVISOR: coverage & follow-ups
└──────────────┘
     │
     ▼
┌──────────────┐
│ Proof Advisor│ ◄── ADVISOR: reproduction steps (proposed)
└──────────────┘

On-demand (via chat):
  Coach ◄── AGENT: conversational explainer (proposed)
  Drift Advisor ◄── ADVISOR: cross-engagement delta (proposed)
```

---

## Naming Conventions

- Agents are named by role: Verifier, Adjudicator, Triage, Coach.
- Gates are named by what they guard: Guardian (scope), Check Policy Gate (org rules).
- Advisors are named by what they analyze: ScanAdvisor, Consistency Advisor, Drift Advisor.

Avoid calling non-agents "agents." If a component doesn't use an LLM, it
isn't an agent. This keeps the taxonomy honest and the architecture
self-documenting.

---

## Relationship to AgentType Enum

The current `AgentType` enum in `app/models.py` conflates all component types.
Phase 26 proposes refactoring this into a `ComponentType` enum (or splitting
into `AgentType`, `GateType`, `AdvisorType`). Until that refactor lands, new
components should still be registered in `AgentType` but documented with their
true taxonomy classification here.

Current enum state and target classification:

| Enum value | Current name | True type | Status |
|------------|-------------|-----------|--------|
| `SCOUT` | Scout | — | **Remove** (dead code, never implemented) |
| `VERIFIER` | Verifier | Agent | Implemented |
| `CHAINSMITH` | Chainsmith | Agent | Implemented |
| `GUARDIAN` | Guardian | Gate | Implemented |
| `ADJUDICATOR` | Adjudicator | Agent | Implemented |
| `TRIAGE` | Triage | Agent | Implemented |
| `PROOF_ADVISOR` | Proof Advisor | Advisor | Not implemented |
