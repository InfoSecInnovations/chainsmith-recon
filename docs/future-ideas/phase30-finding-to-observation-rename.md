# Phase 30 — Rename "Finding" to "Observation"

**Supersedes:** Phase 27 Item 4 (Unify Finding models)
**Should complete before:** Phase 25 (Test Granularity), Phase 29
(Test Authenticity)

## Motivation

"Finding" carries legal and audit weight — in NIST, SOC 2, and ISO 27001
contexts it implies a validated deficiency requiring remediation. Chainsmith
is an automated recon tool whose output has not been human-validated. Using
"finding" overclaims the authority of the results and could create liability
exposure.

"Observation" is what auditors use *before* findings are confirmed. It
signals "the tool saw this, a human should evaluate it." The codebase
already describes the Finding class as *"a security-relevant observation
from a check"* (`app/checks/base.py:93`).

This phase also consolidates the triple Finding definition (Phase 27
Item 4) — since we're touching every reference anyway, unification
happens as part of the rename rather than as a separate pass.

### Why not "Result"?

`CheckResult` is the return type of every check. It *contains* findings.
`result.findings` appears 803 times. Renaming Finding to Result produces
`result.results` everywhere and collides with `AdjudicationResult`.
"Observation" has zero existing class/type/route/DB usage in the codebase.


## Scope

### What changes

| Layer | Items | Est. references |
|-------|-------|-----------------|
| Class definitions | 4 classes renamed | 4 |
| Related classes | 7 (enums, response, config, repository, detail, history, override) | 7 |
| `result.findings` field | Renamed to `result.observations` on CheckResult | ~803 |
| Import statements | Files importing Finding | ~27 |
| DB tables | 3 tables renamed | 3 |
| DB columns | Columns with "finding" in name | ~15 |
| DB indexes | Indexes with "finding" in name | ~7 |
| Scenario services | `FindingsConfig`, `is_finding_active()`, `SessionState.active_findings`, env vars | ~30 refs |
| Migrations | None needed (delete old DB, rebuild) | 0 |
| API routes | 9 endpoints under `/api/v1/findings/` | 9 |
| Route file | `app/routes/findings.py` → `app/routes/observations.py` | 1 |
| CLI commands | `findings` group + subcommands | 4 |
| CLI client methods | `set_finding_override`, etc. | 3 |
| State fields | `state.findings` list | 1 |
| Helper module | `app/lib/findings.py` → `app/lib/observations.py` | 1 |
| Frontend HTML | 5 files | ~100 refs |
| Frontend JS | 11 files | ~50 refs |
| Frontend CSS | 2 files, `.finding-*` classes | ~15 classes |
| Tests | 40+ files | ~200 refs |
| Documentation | 10+ markdown files | ~50 refs |

### What does NOT change

- `CheckResult` stays `CheckResult` (it's a check execution result, not
  a security observation)
- `AdjudicationResult` stays `AdjudicationResult`
- `FindingSeverity` → `ObservationSeverity` (the severity concept stays,
  only the prefix changes)
- Severity values ("info", "low", "medium", "high", "critical") stay
- Fingerprint logic stays (deduplication mechanism is unrelated to naming)


## Class Consolidation (formerly Phase 27 Item 4)

Today there are three classes named `Finding` plus one that should be
unified during the rename:

| Current | Location | Role | After rename |
|---------|----------|------|-------------|
| `Finding` (dataclass) | `app/checks/base.py:91` | Runtime check output | `Observation` — becomes the single canonical definition |
| `Finding` (Pydantic) | `app/models.py:125` | API/agent model | `Observation` (orchestration-layer model — same name, different module from the dataclass; distinct by import path) |
| `Finding` (SQLAlchemy) | `app/db/models.py:66` | DB persistence | `ObservationRecord` (ORM models conventionally use a suffix to distinguish from domain models) |
| `FindingDetail` | `app/api_models.py:122` | API response schema | `ObservationDetail` (thin response wrapper) |

### Target structure

```
app/checks/base.py        →  Observation (canonical dataclass)
app/models.py              →  ObservationSeverity, ObservationStatus,
                              ObservationsResponse
app/db/models.py           →  ObservationRecord, ObservationStatusHistory,
                              ObservationOverride
app/db/repositories.py     →  ObservationRepository, ObservationOverrideRepository
app/api_models.py          →  ObservationDetail
app/lib/observations.py    →  build_observation(), make_observation_id(),
                              make_observation_id_hashed(), validate_severity()
```

### Field rename on CheckResult

```python
# Before
@dataclass
class CheckResult:
    findings: list[Finding] = field(default_factory=list)

# After
@dataclass
class CheckResult:
    observations: list[Observation] = field(default_factory=list)
```

This is the highest-churn single change (~803 references to
`result.findings` across ~100 check implementation files). Every check's
`run()` method appends to `result.findings`.


## Database Migration (simplified)

**No production data exists.** Instead of writing ALTER TABLE/INDEX
migrations with downgrade paths, we:

1. Rename all ORM classes and table/column/index names in `app/db/models.py`
   to use "observation" (done in Wave 1).
2. Delete the old database file (if any).
3. Let SQLAlchemy `create_all()` build fresh tables with the new names.
4. No migration script needed. No downgrade path needed.

### ORM renames in `app/db/models.py`

| Before | After |
|--------|-------|
| `Finding` (class) | `ObservationRecord` |
| `findings` (table) | `observations` |
| `FindingStatusHistory` | `ObservationStatusHistory` |
| `finding_status_history` (table) | `observation_status_history` |
| `FindingOverride` | `ObservationOverride` |
| `finding_overrides` (table) | `observation_overrides` |
| `finding_id` column on `adjudication_results` | `observation_id` |
| `finding_ids` column on `chains` | `observation_ids` |
| All `idx_finding*` / `idx_fsh_*` indexes | `idx_observation*` / `idx_osh_*` |


## API Route Changes

### Endpoint renames

| Before | After |
|--------|-------|
| `GET /api/v1/findings` | `GET /api/v1/observations` |
| `GET /api/v1/findings/by-host` | `GET /api/v1/observations/by-host` |
| `GET /api/v1/findings/{id}` | `GET /api/v1/observations/{id}` |
| `GET /api/v1/findings/overrides` | `GET /api/v1/observations/overrides` |
| `PUT /api/v1/findings/{fp}/override` | `PUT /api/v1/observations/{fp}/override` |
| `DELETE /api/v1/findings/{fp}/override` | `DELETE /api/v1/observations/{fp}/override` |
| `GET /api/v1/findings/{fp}/history` | `GET /api/v1/observations/{fp}/history` |
| `GET /api/v1/scans/{id}/findings` | `GET /api/v1/scans/{id}/observations` |
| `GET /api/v1/scans/{id}/findings/by-host` | `GET /api/v1/scans/{id}/observations/by-host` |

### Route file

`app/routes/findings.py` → `app/routes/observations.py`

Update `app/routes/__init__.py` to import from the new module.

### JSON response keys

Any response body fields named `findings` or `findings_count` rename to
`observations` and `observations_count`.


## CLI Changes

| Before | After |
|--------|-------|
| `chainsmith findings accept` | `chainsmith observations accept` |
| `chainsmith findings false-positive` | `chainsmith observations false-positive` |
| `chainsmith findings reopen` | `chainsmith observations reopen` |
| `chainsmith findings overrides` | `chainsmith observations overrides` |

### CLI client methods

| Before | After |
|--------|-------|
| `set_finding_override()` | `set_observation_override()` |
| `remove_finding_override()` | `remove_observation_override()` |
| `list_finding_overrides()` | `list_observation_overrides()` |

### CLI output strings

| Before | After |
|--------|-------|
| `"Finding {fp} marked as accepted"` | `"Observation {fp} marked as accepted"` |
| `"Finding Overrides ({n} total)"` | `"Observation Overrides ({n} total)"` |


## Frontend Changes

### HTML files (5 files)

- `static/findings.html` → `static/observations.html`
- Update all `<title>`, heading, label, and placeholder text
- Update `static/index.html`, `static/scan.html`, `static/trend.html`,
  `static/settings.html` — links and references to findings page

### JavaScript files (11 files)

- `static/js/api.js` — API endpoint URLs, function names, response key
  access (`.findings` → `.observations`)
- Visualization files (`viz-fullscreen.js`, `host-table.js`, `treemap.js`,
  `coverage.js`, `radar.js`, `timeline.js`, `viz-common.js`,
  `chains-sankey.js`, `heatmap.js`, `trend-charts.js`) — variable names,
  data access patterns, chart labels

### CSS files (2 files)

Rename all `.finding-*` classes to `.observation-*`:

| Before | After |
|--------|-------|
| `.finding-item` | `.observation-item` |
| `.finding-title` | `.observation-title` |
| `.finding-badge` | `.observation-badge` |
| `.finding-severity-dot` | `.observation-severity-dot` |
| (etc. — ~15 classes) | |

Update references in HTML and JS files that use these class names.


## State Changes

```python
# app/state.py
# Before
findings: list[dict] = []

# After
observations: list[dict] = []
```

Update all references to `state.findings` across the codebase.


## Implementation Plan

### Wave 0 — Baseline (do not skip)

1. Run full test suite: `pytest tests/ --tb=short -q`
2. Record pass/fail/skip counts — this is the reference for the phase.
3. Commit the baseline counts somewhere recoverable (e.g., a comment
   in the PR description).

### Wave 1 — Core model rename + unification

Rename and consolidate the class definitions. This is the foundation
everything else builds on.

1. `app/checks/base.py` — Rename `Finding` → `Observation`. Update
   `CheckResult.findings` → `CheckResult.observations`.
2. `app/models.py` — Rename `Finding` → `Observation`,
   `FindingSeverity` → `ObservationSeverity`,
   `FindingStatus` → `ObservationStatus`,
   `FindingsResponse` → `ObservationsResponse`.
3. `app/db/models.py` — Rename ORM classes and table names.
4. `app/api_models.py` — Rename `FindingDetail` → `ObservationDetail`.
5. `app/lib/findings.py` — Rename file to `observations.py`, rename
   functions: `build_finding` → `build_observation`,
   `make_finding_id` → `make_observation_id`,
   `make_finding_id_hashed` → `make_observation_id_hashed`.
6. The dataclass `Observation` (base.py) and Pydantic `Observation`
   (models.py) stay as separate classes — they serve different layers.
   No merge. Both get renamed, distinguished by import path.

**Verify:** `python -c "from app.checks.base import Observation"` works.

### Wave 2 — Persistence layer

1. `app/db/models.py` — Rename ORM classes, table names, column names,
   and index names (see "Database Migration" section above). Already
   started in Wave 1; this wave finishes the ORM layer.
2. `app/db/repositories.py` — Rename `FindingRepository` →
   `ObservationRepository`, `FindingOverrideRepository` →
   `ObservationOverrideRepository`. Rename all methods and helper
   functions.
3. Delete old database file(s) if present. Let `create_all()` rebuild.
4. Delete or skip any migration files that reference old table names
   (no production data to preserve).

**Verify:** Repository unit tests pass (after updating test references).

### Wave 3 — Check implementations (highest volume)

This is the big wave: ~100 check files, ~803 `result.findings` references.

1. Global find-and-replace `result.findings` → `result.observations`
   across `app/checks/`.
2. Update imports: `from app.checks.base import Finding` →
   `from app.checks.base import Observation`.
3. Update any local variable names: `finding =` → `observation =`,
   `findings =` → `observations =` where they refer to the domain
   concept (not loop variables where the name is incidental).

**Strategy:** This wave is mechanical. Use IDE/editor find-and-replace
with review. The patterns are consistent enough for bulk replacement:

```
result.findings.append(  →  result.observations.append(
result.findings.extend(  →  result.observations.extend(
result.findings = [      →  result.observations = [
len(result.findings)     →  len(result.observations)
```

**Verify:** `pytest tests/checks/ -q` passes.

### Wave 3b — Scenario services

The scenario services subsystem uses "finding" to mean "a simulated
vulnerability the target service can expose." Rename for consistency.

1. `app/scenario_services/common/config.py`:
   - `FindingsConfig` → `ObservationsConfig`
   - `RANDOMIZE_FINDINGS` → `RANDOMIZE_OBSERVATIONS`
   - `is_finding_active()` → `is_observation_active()`
   - `get_active_findings()` → `get_active_observations()`
   - `_select_random_findings()` → `_select_random_observations()`
   - `SessionState.active_findings` → `SessionState.active_observations`
   - `ScenarioConfig.findings` → `ScenarioConfig.observations`
   - Update all comments, docstrings, and variable names.
2. All scenario service files that call `is_finding_active()` or
   import from this module — update imports and call sites.
3. `scenario.json` files — rename `"findings"` key to `"observations"`
   in manifest schemas (if any exist).

**Note:** The env var `RANDOMIZE_FINDINGS` is an external interface.
Since there are no production deployments, rename it too. If we later
need backwards compat, handle it then.

**Verify:** Scenario service tests pass (if any). Manual check that
`is_observation_active()` resolves correctly.

### Wave 4 — Engine, agents, state, and orchestration

1. `app/state.py` — Rename `findings` field.
2. `app/engine/` — Update scanner, adjudication references.
3. `app/agents/` — Update verifier, adjudicator, chainsmith references.
4. `app/checks/runner.py` — Rename `self.findings`, `finding_counter`.
5. `app/checks/chain.py` — Update chain-related finding references.
6. `app/scan_advisor.py` — Update advisor trigger references.
7. `app/reports.py` — Update report generation references.

**Verify:** `pytest tests/core/ tests/scanning/ -q` passes.

### Wave 5 — API routes and CLI

1. Rename `app/routes/findings.py` → `app/routes/observations.py`.
2. Update all route paths, function names, response keys.
3. Update `app/routes/__init__.py` router registration.
4. Update `app/routes/scans.py` — finding override routes.
5. Update `app/cli.py` — rename `findings` group to `observations`.
6. Update `app/cli_client.py` — rename client methods.

**Verify:** Start server, hit renamed endpoints manually or with a
quick curl script.

### Wave 6 — Frontend

1. Rename `static/findings.html` → `static/observations.html`.
2. Update all HTML files — text, links, IDs, data attributes.
3. Update all JS files — API URLs, variable names, response key access.
4. Update all CSS files — class name renames.
5. Update any server-side template rendering that references the old
   HTML filename.

**Verify:** Load UI in browser. Check observations page, scan detail,
trend page, dashboard.

### Wave 7 — Tests

1. Bulk rename across `tests/` — same mechanical replacements as Wave 3.
2. Update test fixture names and conftest helpers.
3. Update assertion strings that check for "finding" in output text.

**Verify:** `pytest tests/ --tb=short -q` — counts must match Wave 0
baseline.

### Wave 8 — Documentation and cleanup

1. Update all markdown files in `docs/`.
2. Search for any remaining "finding" references (case-insensitive grep).
3. Update Phase 27 doc to mark Item 4 as "Superseded by Phase 30".
4. Delete this planning doc or move to `docs/completed/`.

**Verify:** `grep -ri "finding" app/ tests/ static/` returns zero
false positives (some legitimate uses may remain in English prose —
review manually).


## Principles

- **Green-to-green.** Every wave must reproduce the baseline test counts.
- **One wave = one commit.** Each wave is independently revertible.
- **Mechanical over clever.** Use bulk find-and-replace, not regex
  wizardry. Review diffs visually.
- **Don't refactor test logic.** This phase renames. Phase 29 improves
  test quality. Keep them separate.
- **Unify during rename.** The class consolidation (Phase 27 Item 4)
  happens in Wave 1, not as a separate pass.


## Risk & Rollback

- **Medium risk.** The change is conceptually simple (rename) but
  touches many files. The main risk is missing a reference and breaking
  something silently.
- **No migration risk.** No production data — DB is rebuilt from scratch.
- **Git rollback.** Each wave is one commit. `git revert` restores any
  wave independently.
- **Grep is your friend.** After each wave, `grep -ri "finding" <dir>`
  to catch stragglers.


## Resolved Questions

- [x] **Can the two Finding classes merge?** No. The dataclass
      (`app/checks/base.py`) is a lightweight check output (id, title,
      description, severity, evidence, target, check_name). The Pydantic
      model (`app/models.py`) is a rich domain object with verification,
      adjudication, hallucination tracking, chain building, and
      severity_multiplier. They serve different layers. **Decision:** keep
      both — rename to `Observation` (dataclass) and `ObservationDetail`
      (Pydantic, replacing the current `FindingDetail` in api_models.py).
      The Pydantic `Finding` in models.py becomes `Observation` as well
      (it is the orchestration-layer model, distinct from the check-output
      dataclass by module, not by name).
- [x] **Migration strategy?** No production data exists anywhere. No need
      for ALTER TABLE/INDEX migrations or downgrade paths. Delete the old
      database and rebuild with new names via `create_all()`. See
      simplified "Database Migration" section below.
- [x] **API deprecation period?** Clean break. Product is pre-release
      with no external consumers.
- [x] **FindingsConfig role?** This is the scenario services subsystem
      (`app/scenario_services/common/config.py`). It controls which
      simulated vulnerabilities target Docker services expose during a
      session (e.g., `is_finding_active("cors_misconfigured")`). This is
      a different concept from scanner output, but rename it anyway for
      consistency — the cognitive overhead of "finding means different
      things in different subsystems" isn't worth it. Adds a new wave
      (Wave 3b) for the scenario services rename.


## Success Criteria

- [ ] Zero classes, variables, routes, tables, or columns named "finding"
      remain (outside English prose in comments/docs where appropriate)
- [ ] `pytest tests/` produces identical pass/fail/skip counts to baseline
- [ ] DB migration runs cleanly up and down
- [ ] All API endpoints respond at new paths
- [ ] CLI `chainsmith observations` subcommands work
- [ ] UI loads and displays observations correctly
- [ ] `grep -ri "finding" app/ static/` returns only false positives
      (English prose, not code identifiers)
