# Phase 48 — Oversight: No Dark Code

## Goal

Eliminate "dark" code — modules, checks, agents, or scripts whose behavior is
not documented or verified. Every non-library file should have a readable
contract, every public surface should have a spec, and every user-facing
workflow should have an end-to-end test backing it.

This phase is about *understanding*, not runtime visibility. Observability
(logs, metrics, telemetry) is Phase 49.

## Motivation

Chainsmith has grown fast through Phases 9–47: swarm, agents, advisors,
scan history, triage, operator chat, check restructuring. Internal contracts
are mostly tribal knowledge. New contributors (human or AI) re-derive the
architecture from source every time, and regressions slip in where two
modules disagree about an invariant no one wrote down.

## Scope

### Workstream A — API specification (generated)

1. Generate OpenAPI 3.1 from the FastAPI route definitions (FastAPI emits this
   natively at `/openapi.json`; commit a snapshot and diff it in CI).
2. Hand-written **API overview** doc: auth model, scan lifecycle, swarm
   enrollment, streaming endpoints, error conventions. Narrative only —
   schemas come from the generated spec.
3. CI check: fail if routes change without the committed OpenAPI snapshot
   being regenerated.

### Workstream B — Architecture map + module contracts

1. **Top-level architecture map** (`docs/architecture/overview.md`):
   describes the *target* state post-ScanContext refactor, not today's
   singleton. Components, data flow, persistence boundaries, agent/swarm
   topology.
2. **Per-module contracts** (`docs/architecture/modules/<module>.md`):
   one file per significant module. Sections: purpose, inputs, outputs,
   invariants, side effects, known gotchas.
3. Library modules are covered here. Individual library *files* are not —
   the module contract is the unit.

### Workstream C — Per-unit contracts (tiered)

Three tiers to keep this tractable:

1. **Checks** — lightweight contract, template-driven, likely auto-stubbed
   from the check registry. Fields: inputs consumed, observations produced,
   preconditions, side effects, typical runtime.
   - Open question: count checks first. If >100, the template must be
     near-zero-cost to fill in or this becomes busywork.
2. **Agents / swarm workers** — fuller contract: lifecycle, messages in/out,
   state ownership, failure modes.
3. **Functional scripts** (entrypoints, CLI tools, one-shots) — short header
   comment: what this does, when to run it, what it touches. No separate doc.

### Workstream D — Test expansion

1. **Unit tests** — continue current practice. Phase 29 rule stands: tests
   change, check implementations don't.
2. **Orchestrator-level E2E** (fast tier): spin up the app with mocked checks,
   drive scans through the API, assert scan lifecycle + persistence behavior.
   Runs in CI on every PR.
3. **Full-stack E2E** (slow tier): real containers, real checks, against a
   **dedicated minimal test scenario** (not fakobanko — too heavy). Scope:
   2–3 services, deterministic, boots in seconds. Runs nightly or on-demand.
4. Workflow coverage matrix: enumerate user-facing workflows (start scan,
   pause/resume, swarm enroll, triage, export report) and mark which tier
   covers each. Gaps become tickets.

## Deliverables

- `openapi.json` committed at repo root or `docs/api/`.
- `docs/api/overview.md`.
- `docs/architecture/overview.md` + `docs/architecture/modules/*.md`.
- `docs/contracts/checks/*.md` (or a single generated index — TBD after count).
- `docs/contracts/agents/*.md`.
- `tests/e2e/orchestrator/` — mocked-check E2E suite.
- `tests/e2e/fullstack/` + `scenarios/minimal/` — real-stack E2E suite and its
  fixture scenario.
- `docs/testing/workflow-coverage.md` — the matrix.

## Sequencing

1. Count checks and agents; decide contract template shape.
2. API spec generation (smallest, highest-leverage, unblocks external consumers).
3. Architecture map + module contracts (unblocks everything downstream).
4. Minimal E2E scenario + orchestrator E2E harness.
5. Per-unit contracts (can parallelize across checks/agents once templates land).
6. Full-stack E2E suite.
7. Workflow coverage matrix + gap tickets.

## Open questions

- Do check contracts live alongside the check source (header docstring +
  generator) or as separate markdown? Co-located drifts less.
- Should the architecture map be authored before or after the ScanContext
  refactor lands? Drafting against the target state risks documenting
  vaporware; drafting against today's state guarantees a rewrite.
- CI budget for the slow E2E tier — nightly only, or gated label on PRs?
- Does the minimal scenario need its own check subset, or can it reuse a
  tagged slice of the existing registry?

## Non-goals

- Runtime observability (Phase 49).
- Rewriting checks or modules for clarity — documentation only, except where
  a contract exposes a genuine bug.
- Public-facing API docs site. Internal markdown is enough for now.
