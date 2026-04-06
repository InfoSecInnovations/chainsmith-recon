# Phase 26 — Model Review

The data models in `app/models.py` were written when Chainsmith had four
components: Scout, Verifier, Chainsmith, and Guardian. Scout is already gone
(replaced by the deterministic ScanAdvisor). More agents and deterministic
scripts are coming. The models need a review pass to keep up.

## Problems

### 1. AgentType is stale and under-specified

```python
class AgentType(StrEnum):
    SCOUT = "scout"        # dead — ScanAdvisor replaced it
    VERIFIER = "verifier"
    CHAINSMITH = "chainsmith"
    GUARDIAN = "guardian"
```

- `SCOUT` still exists but nothing uses it as a class.
- No entries for ScanAdvisor, Proof Advisor, Coach, Adjudicator, or any
  future additions.
- No distinction between AI agents (Verifier, Chainsmith, Proof Advisor,
  Coach) and deterministic components (Guardian, ScanAdvisor). This matters
  for model selection, cost tracking, and understanding what's LLM-driven
  vs rule-based.

### 2. EventType doesn't cover new pipeline stages

Current events map to the original Scout/Verifier/Chainsmith flow. Missing
events for at least:

- Adjudicator decisions
- Proof guidance lifecycle
- Coach interactions
- ScanAdvisor recommendations

### 3. Finding.discovered_by assumes an AI agent

`discovered_by: AgentType` was written when Scout (an AI agent) produced
findings. Now deterministic checks produce findings. The field name and type
still work, but the semantics shifted — worth documenting or reconsidering.

### 4. No shared model for "component" identity

Agents, scripts, and checkers all emit events, produce or consume findings,
and need entries in the type enum. There's no unified concept of "a thing
that participates in the pipeline" — just AgentType used for everything.


## Decisions to make

### A. Rename or split AgentType?

Options:

1. **Rename to `ComponentType`** — single enum, everything in it, name
   reflects that not all entries are AI agents.
2. **Split into `AgentType` + `ScriptType`** — separate enums for AI agents
   and deterministic scripts. Cleaner semantically, but now `Finding.discovered_by`
   and `AgentEvent.agent` need a union type or a shared base.
3. **Keep `AgentType`, just add entries** — least churn, but the name
   becomes increasingly misleading.

### B. How to handle EventType growth?

Options:

1. **Keep adding to the flat enum** — simple, but it's already at 13 entries
   and will grow fast with each new component.
2. **Namespace by component** — e.g., `ADJUDICATOR_DECISION`,
   `PROOF_GUIDANCE_REQUESTED`, `COACH_QUERY`. Still flat, but naming convention
   groups them.
3. **Structured event type** — e.g., `(component, action)` tuple instead of
   a single string. More flexible, but breaks the current StrEnum pattern.

### C. Should models enforce component capabilities?

Some components use tools, some don't. Some are LLM-backed, some aren't.
Should the model layer express this, or should that stay in the component
implementations?

### D. Finding provenance

Now that findings come from deterministic checks rather than an AI agent,
should the model capture more about *how* a finding was produced? e.g.,
which check class generated it, what tool was used, whether it was
LLM-assisted or purely rule-based.


## Scope

This phase is a review and refactor of `app/models.py` and any files that
reference the changed types. It should be done in a single pass so that
downstream code doesn't have to deal with partial migrations.

Affected files (at minimum):
- `app/models.py` — enum and model changes
- `app/guardian.py` — references `AgentType.GUARDIAN`
- `app/scan_advisor.py` — should be represented in the type system
- `app/engine/scanner.py` — emits events, produces findings
- `app/routes/advisor.py` — may reference types
- All future phase docs that propose new agents or scripts


## Dependencies

- None hard — this can be done at any time.
- Best done *before* implementing Adjudicator (Phase 21), Proof Advisor, or
  Coach (Phase 22) so new components land on a clean type system.


## Open questions

- Should we version the models for backward compatibility with existing
  persisted sessions, or is a clean break acceptable?
- Is there a case for a component registry (runtime registration of
  capabilities) rather than a static enum?
