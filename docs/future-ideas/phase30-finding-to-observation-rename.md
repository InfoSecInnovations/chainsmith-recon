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
| Migrations | New migration for renames | 1 new |
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
| `Finding` (Pydantic) | `app/models.py:125` | API/agent model | **Merge into canonical** `Observation` or keep as `ObservationDetail` if extra fields are needed |
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


## Database Migration

New migration `005_rename_findings_to_observations.py`:

### Table renames

```sql
ALTER TABLE findings RENAME TO observations;
ALTER TABLE finding_status_history RENAME TO observation_status_history;
ALTER TABLE finding_overrides RENAME TO observation_overrides;
```

### Column renames

```sql
-- observations table (formerly findings)
-- No "finding"-named columns in this table — columns are clean.

-- observation_status_history (formerly finding_status_history)
-- No "finding"-named columns — uses fingerprint, scan_id, status.

-- observation_overrides (formerly finding_overrides)
-- No "finding"-named columns — uses fingerprint, status, reason.

-- adjudication_results table
ALTER TABLE adjudication_results RENAME COLUMN finding_id TO observation_id;

-- chains table
-- finding_ids JSON column → observation_ids
-- JSON column rename requires: add new column, copy data, drop old, rename
ALTER TABLE chains ADD COLUMN observation_ids TEXT;
UPDATE chains SET observation_ids = finding_ids;
ALTER TABLE chains DROP COLUMN finding_ids;
```

### Index renames

```sql
ALTER INDEX idx_findings_scan_id RENAME TO idx_observations_scan_id;
ALTER INDEX idx_findings_severity RENAME TO idx_observations_severity;
ALTER INDEX idx_findings_host RENAME TO idx_observations_host;
ALTER INDEX idx_findings_fingerprint RENAME TO idx_observations_fingerprint;
ALTER INDEX idx_finding_overrides_fingerprint RENAME TO idx_observation_overrides_fingerprint;
ALTER INDEX idx_fsh_fingerprint RENAME TO idx_osh_fingerprint;
ALTER INDEX idx_fsh_scan_id RENAME TO idx_osh_scan_id;
```

**Note:** Index rename syntax varies by database engine. If using SQLite
(which doesn't support `ALTER INDEX`), indexes must be dropped and
recreated. The migration should detect the engine and use the appropriate
approach.

### Downgrade

The migration must include a reversible downgrade that restores the
original names.

**Note:** The `finding_overrides` table is defined in the ORM but has no
migration file yet. This migration should also handle creating it if it
doesn't exist, or a separate migration (005a) should create it first.


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
6. Consolidate the three Finding classes into two (domain + ORM) as
   part of the rename. If `app/models.py:Finding` and
   `app/checks/base.py:Finding` can merge, do it now.

**Verify:** `python -c "from app.checks.base import Observation"` works.

### Wave 2 — Persistence layer

1. `app/db/repositories.py` — Rename `FindingRepository` →
   `ObservationRepository`, `FindingOverrideRepository` →
   `ObservationOverrideRepository`. Rename all methods and helper
   functions.
2. Create migration `005_rename_findings_to_observations.py`.
3. Run migration against dev database. Verify tables renamed.

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
- **Migration rollback.** The DB migration must include a downgrade path.
- **Git rollback.** Each wave is one commit. `git revert` restores any
  wave independently.
- **Grep is your friend.** After each wave, `grep -ri "finding" <dir>`
  to catch stragglers.


## Open Questions

- [ ] Can the Pydantic `Finding` in `app/models.py` and the dataclass
      `Finding` in `app/checks/base.py` be merged into a single class?
      They have overlapping but not identical fields. If not, keep both
      as `Observation` (base) and `ObservationDetail` (extended).
- [ ] The `finding_overrides` table has no migration yet. Should
      migration 005 create it fresh with the new name, or should a
      separate migration create it under the old name first for
      existing installs?
- [ ] Should the API serve a deprecation period with both
      `/api/v1/findings` and `/api/v1/observations`? Or clean break?
      (Recommendation: clean break — no external consumers yet.)
- [ ] The `FindingsConfig` in `app/scenario_services/common/config.py`
      needs renaming too — confirm this file's role before renaming.


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
