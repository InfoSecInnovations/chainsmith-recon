# Phase 26 — Model Review

The data models in `app/models.py` have drifted as components were added and
removed. `AgentType` is misleading (it covers agents, gates, and advisors),
dead references to "scout" persist as type violations, `EventType` has 9
unused members, and `Observation.discovered_by` is vestigial now that checks
are the sole discovery mechanism. This phase cleans up the type system so
new components land on honest foundations.


## Current state (as of code audit 2026-04-10)

### AgentType enum (8 entries)

```python
class AgentType(StrEnum):
    VERIFIER = "verifier"              # Agent (app/agents/verifier.py)
    CHAINSMITH = "chainsmith"          # Agent (app/agents/chainsmith.py)
    GUARDIAN = "guardian"              # Gate  (app/guardian.py)
    ADJUDICATOR = "adjudicator"        # Agent (app/agents/adjudicator.py)
    TRIAGE = "triage"                  # Agent (app/agents/triage.py)
    CHECK_PROOF_ADVISOR = "check_proof_advisor"  # Advisor (app/advisors/check_proof.py)
    RESEARCHER = "researcher"          # Agent (app/agents/researcher.py)
    COACH = "coach"                    # Agent (app/agents/coach.py)
```

Previously included `SCOUT` — already removed. `model_scout` config slot —
already removed.

### EventType enum (34 entries)

16 generic + component lifecycle events, 7 chainsmith events, 11 others.
**9 are never emitted:**

| Dead event | Reason |
|-----------|--------|
| `OBSERVATION_DISCOVERED` | Checks are deterministic; no "discovery" event to emit |
| `CHAIN_IDENTIFIED` | Chainsmith uses CHAINSMITH_* events instead |
| `SCOPE_APPROVED` | Guardian only emits SCOPE_VIOLATION; approved is implicit |
| `SCOPE_DENIED` | Same — violations are the only interesting signal |
| `PROOF_GUIDANCE_REQUESTED` | CheckProofAdvisor is deterministic, never emits events |
| `PROOF_GUIDANCE_GENERATED` | Same |
| `COACH_QUERY` | Coach is conversational; events not useful |
| `COACH_RESPONSE` | Same |
| `CHAINSMITH_FIX_SUGGESTED` | Chainsmith emits FIX_APPLIED but not FIX_SUGGESTED |

### Key model fields that reference AgentType

| Model | Field | Default | Location |
|-------|-------|---------|----------|
| `Observation` | `discovered_by: AgentType` | (required) | `app/models.py:164` |
| `Observation` | `verified_by: AgentType \| None` | `None` | `app/models.py:174` |
| `AdjudicatedRisk` | `adjudicated_by: AgentType` | `AgentType.ADJUDICATOR` | `app/models.py:227` |
| `AttackChain` | `identified_by: AgentType` | `AgentType.CHAINSMITH` | `app/models.py:272` |
| `AgentEvent` | `agent: AgentType` | (required) | `app/models.py:418` |
| `RouteDecision` | `target: AgentType \| None` | `None` | `app/models.py:475` |
| `DirectiveRequest` | `agent: AgentType` | (required) | `app/models.py:517` |

### Components that exist today

| Component | Type | File | In AgentType? | Emits events? |
|-----------|------|------|---------------|---------------|
| Verifier | Agent | `app/agents/verifier.py` | Yes | Yes (16 sites) |
| Chainsmith | Agent | `app/agents/chainsmith.py` | Yes | Yes (10 sites) |
| Adjudicator | Agent | `app/agents/adjudicator.py` | Yes | Yes (4 sites) |
| Triage | Agent | `app/agents/triage.py` | Yes | Yes |
| Researcher | Agent | `app/agents/researcher.py` | Yes | Yes (5 sites) |
| Coach | Agent | `app/agents/coach.py` | Yes | **No** (should emit AGENT_START/COMPLETE) |
| Guardian | Gate | `app/guardian.py` | Yes | Yes (SCOPE_VIOLATION only) |
| CheckProofAdvisor | Advisor | `app/advisors/check_proof.py` | Yes | No |
| ScanAdvisor | Advisor | `app/scan_advisor.py` | **No** | No |
| Checks (139+) | — | `app/checks/` | No | No (produce Observations) |

### Two Observation types

- **`app/checks/base.Observation`** — dataclass used by checks, has `check_name`
- **`app/models.Observation`** — Pydantic model for DB/API, has `discovered_by: AgentType`

The checks-layer `Observation.check_name` is preserved to the database
(`observations.check_name` column) but repurposed as `observation_type` when
reading back into the Pydantic model. Meanwhile `discovered_by` defaults to
the string `"scout"` in 4 locations — a type violation since SCOUT is no
longer in the enum.

### Hardcoded "scout" references (4 sites)

- `app/engine/adjudication.py:142` — `discovered_by=f.get("discovered_by", "scout")`
- `app/engine/chat.py:520` — `discovered_by="scout"`
- `app/engine/chat.py:633` — `discovered_by="scout"`
- `app/engine/triage.py:249` — `discovered_by=f.get("discovered_by", "scout")`


## Decisions

### A. Rename AgentType to ComponentType — RESOLVED

Rename `AgentType` → `ComponentType`. Single flat enum covering agents, gates,
and advisors. The component taxonomy doc defines the classification; the enum
just identifies components.

Target enum:

```python
class ComponentType(StrEnum):
    # Agents (LLM-powered)
    VERIFIER = "verifier"
    ADJUDICATOR = "adjudicator"
    TRIAGE = "triage"
    CHAINSMITH = "chainsmith"
    RESEARCHER = "researcher"
    COACH = "coach"

    # Gates (deterministic enforcement)
    GUARDIAN = "guardian"

    # Advisors (deterministic analysis)
    CHECK_PROOF_ADVISOR = "check_proof_advisor"
```

Note: `SCAN_ADVISOR` is deferred to Phase 40 (advisor consolidation), which
moves ScanAdvisor into `app/advisors/` and adds it to the enum + chat routing.

### B. EventType cleanup — RESOLVED

Per-event audit. Remove the 9 dead events. Leave the 7 chainsmith events as-is
(they are actively emitted by ChainsmithAgent; renamed from STEWARD_* to
CHAINSMITH_* in Phase 39).

Events to remove:
- `OBSERVATION_DISCOVERED`
- `CHAIN_IDENTIFIED`
- `SCOPE_APPROVED`
- `SCOPE_DENIED`
- `PROOF_GUIDANCE_REQUESTED`
- `PROOF_GUIDANCE_GENERATED`
- `COACH_QUERY`
- `COACH_RESPONSE`
- `CHAINSMITH_FIX_SUGGESTED`

### C. Drop Observation.discovered_by — RESOLVED

Checks are stimulus-response. `discovered_by` is vestigial from the Scout era.
The real provenance is `check_name`, which is already persisted in the DB.

Action:
- Remove `discovered_by: AgentType` from the Pydantic `Observation` model
- Remove the 4 hardcoded `"scout"` fallbacks
- `check_name` continues to serve as observation provenance
- Fix the `check_name` → `observation_type` mapping so these are not conflated
  (see Decision F)
- `verified_by: ComponentType | None` stays — agents still verify observations

### D. Component capabilities — RESOLVED BY TAXONOMY

The component taxonomy defines capabilities by type. The enum identifies
components; the taxonomy classifies them. No enforcement in the enum.

### E. Config ghost cleanup — ALREADY DONE

`model_scout` was removed from `app/config.py` in a prior phase.

### F. Fix check_name / observation_type conflation — NEW

When observations are read from the DB back into the Pydantic model,
`check_name` is being mapped to `observation_type`. These are different
concepts:

- `check_name` = which check produced this observation (e.g., `"port_scan"`)
- `observation_type` = category/kind of observation

The Pydantic `Observation` model should carry `check_name` as its own field,
not have it silently repurposed. Add `check_name: str | None = None` to the
Pydantic model and populate it from the DB record. Review whether
`observation_type` has a distinct purpose or can be removed.

### G. Add AGENT_START/COMPLETE to Coach — NEW

Coach is the only agent that emits zero events. Add `AGENT_START` and
`AGENT_COMPLETE` emissions to `CoachAgent` for lifecycle observability
(usage frequency, error tracking, response latency). No coach-specific
events needed.


## Scope

Single-pass refactor of `app/models.py` and all referencing files.

### Affected files (verified by code scan)

**Must change:**
- `app/models.py` — enum rename, field changes, dead event removal
- `app/agents/verifier.py` — 16 `AgentType` → `ComponentType` sites
- `app/agents/chainsmith.py` — 10 sites
- `app/agents/adjudicator.py` — 4 sites
- `app/agents/triage.py` — 3 sites
- `app/agents/researcher.py` — 5 sites
- `app/agents/coach.py` — AgentType refs + add AGENT_START/COMPLETE events
- `app/guardian.py` — 1 site
- `app/engine/adjudication.py` — remove `discovered_by` / `"scout"` default (line 142)
- `app/engine/chat.py` — remove `discovered_by="scout"` (lines 520, 633) + AgentType refs
- `app/engine/triage.py` — remove `discovered_by` / `"scout"` default (line 249)
- `app/engine/prompt_router.py` — 23 AgentType refs, rename agent_map → component_map

**Must change (tests):**
- `tests/core/test_adjudicator.py` — AgentType refs
- `tests/core/test_triage.py` — AgentType refs
- `tests/core/test_prompt_router.py` — AgentType refs
- `tests/core/conftest.py` — `discovered_by: "test"` in metadata (line 17)

**Should review:**
- `app/checks/base.py` — verify `check_name` propagation is intact
- `app/db/writers.py` — verify `ObservationWriter` passes `check_name` through
- `app/db/repositories.py` — verify `check_name` is returned in observation dicts

**Not affected (confirmed):**
- `app/routes/*` — no direct AgentType or EventType references
- `app/engine/scanner.py` — uses ObservationWriter, no enum refs
- `app/engine/chains.py` — no enum references
- `app/scan_advisor.py` — deferred to Phase 40


## Migration order

1. Add `ComponentType` enum alongside `AgentType` (temporary alias)
2. Add `check_name: str | None` to Pydantic `Observation`, remove `discovered_by`
3. Update all engine files (adjudication, chat, triage) to stop setting `discovered_by`
4. Rename all `AgentType` → `ComponentType` references across agents and tests
5. Remove dead EventType members
6. Add AGENT_START/COMPLETE to Coach
7. Remove the old `AgentType` alias
8. Run full test suite, fix any breakage


## Dependencies

- None hard — can be done at any time.
- Best done *before* Phase 39 (chainsmith consolidation) and Phase 40
  (advisor consolidation) so those phases land on a clean type system.
- Database can be deleted and rebuilt; no migration needed for persisted data.


## Open questions

None — all decisions resolved.
