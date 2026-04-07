# Phase 27 — Architectural Debt Cleanup

A consolidation pass to fix structural issues accumulated during rapid
feature development. These aren't bugs — the tool works — but they create
confusion, hide real behavior, and will compound as the project grows.


## Problems

### 1. Dead scanner files in `app/engine/`

`scanner_foo.py` and `scanner_old.py` are byte-for-byte identical (~16 KB
each), represent the old `CheckRunner` architecture, and are imported by
nothing. They double the size of the engine directory and confuse anyone
trying to understand the scan execution path.

**Fix:** Delete both files. If historical reference is needed, git has them.


### 2. Verification is a no-op

`app/engine/scanner.py:234-242`:

```python
async def run_verification(state):
    state.phase = "verifying"
    state.phase = "done"      # immediately overwrites the line above
    state.status = "complete"
```

This does nothing. The second assignment overwrites the first on the very
next line. Meanwhile `state.verified_count` and `state.verification_total`
exist but are never populated. The old (now-deleted) scanner had a real
implementation.

**Fix:** Either reimplement verification using the logic from the old
scanner (re-probe findings to confirm they're real) or remove the function,
the route that calls it, and the tracking fields from state. Don't leave a
function that pretends to work.


### 3. Duplicate `AttackChain` models

`app/models.py:214` and `app/api_models.py:136` both define
`class AttackChain(BaseModel)` — two independent Pydantic models for the
same concept. They will inevitably drift.

**Fix:** Keep the one in `models.py` as the source of truth. Import it in
`api_models.py` or create a thin response wrapper that delegates to it.


### 4. Triple `Finding` definition

- `app/models.py:125` — domain model (Pydantic)
- `app/db/models.py:66` — persistence model (SQLAlchemy)
- `app/checks/base.py:91` — check framework model

Domain vs. DB separation is defensible. The third `Finding` in
`checks/base.py` is not — it creates an extra translation layer and a
source of field drift.

**Fix:** Have checks produce `app.models.Finding` directly, or define a
minimal `CheckResult` type that is explicitly *not* a Finding and gets
mapped into one by the engine. The current situation where three classes
named `Finding` coexist is a maintenance trap.


### 5. Every route is doubled for fake API versioning

Every endpoint across all 15 route files is registered twice:

```python
@router.post("/api/v1/scan", status_code=202)
@router.post("/api/scan", status_code=202)
```

There is no v2. There is no deprecation timeline. Both resolve to the same
handler. This doubles the OpenAPI spec surface, confuses clients, and isn't
actually versioning — it's decoration.

**Fix:** Pick one scheme and remove the other. If real versioning is needed
later, implement it properly (path prefix, header-based, or separate
routers). Until then, `/api/` without a version number is simpler and
honest.


### 6. Global mutable state backing a REST API

`app/state.py` is a global singleton with 50+ mutable fields and no
locking. The active scan path writes findings to `state.findings` (a
plain list), not to the database. If two scans run concurrently the second
obliterates the first.

The persistence layer (`app/db/`) exists but is used fire-and-forget
*after* the scan completes — it's an audit log, not the source of truth.

**Fix:** This is the largest item. Options:

1. **Session-scoped state:** Create a `ScanSession` keyed by `scan_id`.
   Store active sessions in a dict. Routes look up the session by ID.
   The global singleton goes away.
2. **DB as source of truth:** Write findings to the database as they're
   produced (not fire-and-forget after). Routes query the DB for results.
   State becomes a thin progress tracker.
3. **Accept single-tenancy:** If this is genuinely a single-user CLI tool,
   document that explicitly, remove the concurrent scan pretense
   (`engagement_id`, historical scans UI), and keep the singleton. At
   least the architecture would be honest.

Option 1 is the smallest change that unblocks real concurrency. Option 2 is
the correct long-term answer. Option 3 is fine if nobody needs multi-scan.


### 7. Inconsistent LLM client patterns in agents

`app/agents/chainsmith.py` uses the OpenAI SDK directly:

```python
self.client = AsyncOpenAI(base_url=LITELLM_BASE_URL, api_key="not-needed")
```

`app/agents/adjudicator.py` uses the project's own abstraction:

```python
from app.lib.llm import get_llm_client
```

Two agents in the same directory, two different integration patterns, one
hardcoded dummy API key.

**Fix:** Migrate `chainsmith.py` to use `get_llm_client()`. Remove the
direct `openai` import. The abstraction layer already exists — use it
everywhere.


### 8. Stale import in state.py

`app/state.py:9` imports `CheckRunner` from `app.checks`. The active
scanner uses `CheckLauncher`. `state.runner` is typed as
`CheckRunner | None` but is actually assigned a `CheckLauncher` or
`SwarmRunner` at runtime.

**Fix:** Update the import and type annotation to reflect what's actually
stored. If a common protocol/base class is needed, define one.


### 9. Adjudicator over-engineering (four strategies)

`app/agents/adjudicator.py` (530 lines) implements four adjudication
approaches: `structured_challenge`, `adversarial_debate`,
`evidence_rubric`, and `auto`. The `auto` mode picks one of the other
three based on severity tier.

For a recon tool, this is disproportionate complexity for the question "is
this severity rating correct?" The three non-auto approaches have
duplicated parsing/error-handling logic.

**Fix:** Pick the one approach that works best in practice (likely
`evidence_rubric` — most deterministic, cheapest) and ship that. If
multiple strategies prove valuable after real-world use, re-add them behind
a cleaner interface with shared parsing. Don't ship four strategies before
validating one.


### 10. Feature creep in the route layer

15 route files for a recon tool: `scan.py`, `scans.py` (two files for
overlapping concerns), `findings.py`, `chains.py`, `adjudication.py`,
`advisor.py`, `engagements.py`, `scenarios.py`, `scope.py`,
`compliance.py`, `customizations.py`, `preferences.py`, `checks.py`,
`swarm.py`, plus the `__init__.py` that wires them.

**Fix:** This doesn't need fewer features, it needs fewer files. Merge
related routers:

- `scan.py` + `scans.py` + `checks.py` -> `scanning.py`
- `findings.py` + `customizations.py` -> `findings.py`
- `chains.py` + `adjudication.py` + `advisor.py` -> `analysis.py`
- `engagements.py` + `compliance.py` -> `engagements.py`
- `scope.py` + `preferences.py` -> `config.py`
- `scenarios.py` stays (distinct concern)
- `swarm.py` stays (distinct concern)

7 files instead of 15. Same endpoints, half the cognitive load.


## Prioritization

| Item | Effort | Impact | Status |
|------|--------|--------|--------|
| 1. Delete dead scanners | Minutes | Noise reduction | **Done** (previously deleted) |
| 2. Fix or remove verification | Small | Correctness | **Done** — removed no-op; verification is a future feature |
| 3. Consolidate AttackChain | Small | Prevent drift | **Done** — removed unused duplicate from api_models.py |
| 4. Unify Finding models | Medium | Maintainability | **Superseded** by Phase 30 (Finding → Observation rename + unification) |
| 5. Remove route doubling | Small | API clarity | **Done** — kept /api/v1/, removed unversioned /api/ |
| 6. Fix global state | Large | Correctness | **Deferred** — future session, needs concurrency decision |
| 7. Unify LLM client usage | Small | Consistency | **Done** — chainsmith.py now uses get_llm_client() |
| 8. Fix state.py import | Minutes | Correctness | **Done** — updated to CheckLauncher |
| 9. Simplify adjudicator | Medium | Complexity reduction | **Deferred** — future session, needs usage data |
| 10. Merge route files | Medium | Cognitive load | **Deferred** — future session |


## Dependencies

- Should be done *before* any new feature phases to avoid building on top
  of inconsistent foundations.
- Item 4 (Finding unification) may interact with Phase 26 (model review).
  Coordinate or merge the two efforts.
- Item 6 (global state) should be resolved before swarm mode is considered
  production-ready — swarm inherently means concurrent scans.


## Open questions

- Is multi-scan concurrency a real requirement, or is single-tenancy
  acceptable? This determines the scope of item 6.
- Has anyone validated which adjudication approach (item 9) produces the
  best results? If not, run the comparison before simplifying.
- Are there external clients depending on the `/api/v1/` prefix (item 5)?
  If so, deprecate rather than remove.
