# Phase 26 — Model Review

The data models in `app/models.py` were written when Chainsmith had four
components: Scout, Verifier, Chainsmith, and Guardian. Scout is gone
(replaced by deterministic checks + ScanAdvisor). Adjudicator has since
been added, and more components are planned. The models need a review pass
to keep up.


## Current state (as of code scan)

### AgentType enum (5 entries)

```python
class AgentType(StrEnum):
    SCOUT = "scout"        # dead — no Scout class exists
    VERIFIER = "verifier"  # AI agent (app/agents/verifier.py)
    CHAINSMITH = "chainsmith"  # AI agent (app/agents/chainsmith.py)
    GUARDIAN = "guardian"   # deterministic (app/guardian.py)
    ADJUDICATOR = "adjudicator"  # AI agent (app/agents/adjudicator.py)
```

### EventType enum (16 entries)

```python
class EventType(StrEnum):
    AGENT_START, AGENT_COMPLETE       # generic agent lifecycle
    TOOL_CALL, TOOL_RESULT            # LLM tool use
    OBSERVATION_DISCOVERED/VERIFIED/REJECTED  # observation flow
    HALLUCINATION_CAUGHT              # verifier-specific
    CHAIN_IDENTIFIED                  # chainsmith-specific
    SCOPE_VIOLATION/APPROVED/DENIED   # guardian-specific
    ADJUDICATION_START/COMPLETE       # adjudicator-specific
    SEVERITY_UPHELD/ADJUSTED          # adjudicator-specific
    ERROR, INFO                       # generic
```

### Key model fields that reference AgentType

| Model | Field | Default | Location |
|-------|-------|---------|----------|
| `Observation` (Pydantic) | `discovered_by: AgentType` | (required) | `app/models.py:137` |
| `Observation` (Pydantic) | `verified_by: AgentType \| None` | `None` | `app/models.py:147` |
| `AdjudicatedRisk` | `adjudicated_by: AgentType` | `AgentType.ADJUDICATOR` | `app/models.py:196` |
| `AttackChain` | `identified_by: AgentType` | `AgentType.CHAINSMITH` | `app/models.py:241` |
| `AgentEvent` | `agent: AgentType` | (required) | `app/models.py:257` |

### Components that exist today

Per the [component taxonomy](component-taxonomy.md):

| Component | Taxonomy type | File | In AgentType? | Emits events? |
|-----------|--------------|------|---------------|---------------|
| Verifier | **Agent** | `app/agents/verifier.py` | Yes | Yes (extensive) |
| Chainsmith | **Agent** | `app/agents/chainsmith.py` | Yes | Yes |
| Adjudicator | **Agent** | `app/agents/adjudicator.py` | Yes | Yes |
| Triage | **Agent** | `app/agents/triage.py` | Yes | Yes |
| Guardian | **Gate** | `app/guardian.py` | Yes | Yes (scope violations) |
| ScanAdvisor | **Advisor** | `app/scan_advisor.py` | **No** | No |
| Checks (130+) | — | `app/checks/` | **No** | No (produce Observations) |

### Two Observation types

There are two separate `Observation` classes:
- **`app/checks/base.Observation`** — dataclass used by checks, has `check_name` traceability but no `discovered_by`
- **`app/models.Observation`** — Pydantic model for DB/API, has `discovered_by: AgentType` but no `check_name`

The checks-layer Observation gets converted to dicts by `ObservationWriter` and stored
in the DB. When read back (e.g., in `engine/adjudication.py:142`), `discovered_by`
defaults to `"scout"` — a hardcoded fallback to a dead component.

### Config ghost: `model_scout`

`app/config.py` still has `model_scout` as a LiteLLM model setting (line 79), env var
mapping (`LITELLM_MODEL_SCOUT`, line 305/409), and YAML key (line 25). Nothing uses
this model slot — it's leftover from when Scout was an AI agent.


## Problems

### 1. AgentType is stale

- `SCOUT` exists but no Scout class or usage remains (only the dead default in
  `engine/adjudication.py:142` and test fixtures in `test_adjudicator.py`).
- ScanAdvisor has its own config, class, and route (`app/routes/advisor.py`) but
  no entry in AgentType — it's invisible to the type system.
- No entries planned for Coach or Proof Advisor (both still proposals).
- No distinction between agents (Verifier, Chainsmith, Adjudicator, Triage),
  gates (Guardian), and advisors (ScanAdvisor). The [component taxonomy](component-taxonomy.md)
  now defines this classification. This matters for model selection, cost
  tracking, and understanding what's LLM-driven vs rule-based.

### 2. EventType is growing but manageable

Currently 16 entries. The adjudicator events (ADJUDICATION_START/COMPLETE,
SEVERITY_UPHELD/ADJUSTED) were added cleanly. The enum is still navigable, but
adding events for ScanAdvisor, Coach, and Proof Advisor would push it past 20.
No naming convention separates component-specific events from generic ones.

### 3. Observation.discovered_by assumes an AI agent

`discovered_by: AgentType` was written when Scout produced observations. Now
deterministic checks produce them. The checks-layer `Observation` dataclass
tracks provenance via `check_name`, but this field is lost during the conversion
to the Pydantic model. Meanwhile `discovered_by` gets hardcoded to `"scout"` in
the DB fallback path (`engine/adjudication.py:142`).

### 4. No shared model for "component" identity

Agents, the guardian, the scan advisor, and checkers all participate in the
pipeline. `AgentType` is the only identity enum, but it doesn't cover ScanAdvisor
or individual checks. `AgentEvent.agent` uses it, `Observation.discovered_by`
uses it, but neither can express "check_http_headers found this."


## Decisions to make

### A. Rename or split AgentType?

**Resolved.** The [component taxonomy](component-taxonomy.md) establishes
three component types: **Agents** (LLM-powered), **Gates** (deterministic
policy enforcement), and **Advisors** (deterministic post-hoc analysis).

The recommended approach is **option 1: rename to `ComponentType`** with
all components registered in a single enum, documented with their true
classification. This is the least churn option that also makes the name
honest. Fields like `Observation.discovered_by` and `AgentEvent.agent`
become `ComponentType` references.

Target enum:

```python
class ComponentType(StrEnum):
    # Agents (LLM-powered)
    VERIFIER = "verifier"
    ADJUDICATOR = "adjudicator"
    TRIAGE = "triage"
    CHAINSMITH = "chainsmith"

    # Gates (deterministic enforcement)
    GUARDIAN = "guardian"

    # Advisors (deterministic analysis)
    SCAN_ADVISOR = "scan_advisor"
```

Previous options for reference:

1. ~~**Rename to `ComponentType`**~~ — **selected**
2. **Split into `AgentType` + `ScriptType`** — rejected; union types add
   complexity without proportional benefit.
3. **Keep `AgentType`, just add entries** — rejected; the name is
   increasingly misleading.

### B. How to handle EventType growth?

Options:

1. **Keep adding to the flat enum** — simple, 16 entries is still workable.
2. **Namespace by component** — e.g., `ADJUDICATOR_DECISION`,
   `PROOF_GUIDANCE_REQUESTED`, `COACH_QUERY`. Still flat, but naming convention
   groups them. (The adjudicator events already follow this pattern.)
3. **Structured event type** — e.g., `(component, action)` tuple instead of
   a single string. More flexible, but breaks the current StrEnum pattern.

### C. Should models enforce component capabilities?

**Resolved by taxonomy.** The component taxonomy defines capabilities by
type: agents use LLMs and may use tools; gates and advisors are deterministic.
This distinction lives in the taxonomy documentation and component
implementations, not in the enum itself. The enum identifies components;
the taxonomy classifies them.

### D. Observation provenance

Now that observations come from deterministic checks, the checks-layer
`Observation` already tracks `check_name` but this is lost when writing to
the DB. Two concrete sub-decisions:

1. Should `check_name` be preserved through to the Pydantic `Observation`
   model? (Likely yes — it's already available, just dropped.)
2. Should `discovered_by` change type? Options:
   - Keep as `AgentType` but set to a new `SCANNER` or `CHECK` value
   - Change to `str` for free-form provenance (e.g., `"check_http_headers"`)
   - Change to `ComponentType` if Decision A goes with option 1

### E. Clean up config ghost?

`model_scout` in config serves no purpose. Remove it, or repurpose it for
something else (e.g., a model slot for ScanAdvisor if it ever becomes
LLM-backed)?


## Scope

This phase is a review and refactor of `app/models.py` and any files that
reference the changed types. It should be done in a single pass so that
downstream code doesn't have to deal with partial migrations.

Affected files (confirmed by code scan):

**Must change:**
- `app/models.py` — enum and model changes
- `app/guardian.py` — references `AgentType.GUARDIAN`
- `app/agents/verifier.py` — references `AgentType.VERIFIER` (~16 sites)
- `app/agents/chainsmith.py` — references `AgentType.CHAINSMITH` (~4 sites)
- `app/agents/adjudicator.py` — references `AgentType.ADJUDICATOR` (~6 sites)
- `app/engine/adjudication.py` — hardcoded `"scout"` default on line 142
- `tests/core/test_adjudicator.py` — uses `AgentType.SCOUT` in fixtures

**Should review:**
- `app/config.py` — `model_scout` config slot (lines 25, 79, 203-204, 305-306, 409)
- `app/scan_advisor.py` — should gain a type system entry
- `app/checks/base.py` — `Observation.check_name` should propagate to Pydantic model
- `app/db/writers.py` — `ObservationWriter` is where check_name could be preserved
- `tests/core/conftest.py` — test metadata uses `discovered_by: "test"`

**Not affected (confirmed):**
- `app/routes/*` — no direct references to `AgentType` or `EventType`
- `app/engine/scanner.py` — uses `ObservationWriter` but doesn't set `discovered_by`
- `app/engine/chains.py` — no direct enum references


## Dependencies

- None hard — this can be done at any time.
- Best done *before* implementing Coach (Phase 22) or Proof Advisor so new
  components land on a clean type system.
- Adjudicator is already implemented — its references need migration, not design.


## Open questions

- Should we version the models for backward compatibility with existing
  persisted sessions, or is a clean break acceptable?
- Is there a case for a component registry (runtime registration of
  capabilities) rather than a static enum?
- Should the two `Observation` classes (dataclass in `checks/base.py` vs
  Pydantic in `models.py`) be unified, or is the separation intentional?
