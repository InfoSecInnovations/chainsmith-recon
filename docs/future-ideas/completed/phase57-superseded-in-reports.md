# Phase 57 follow-up: reports handle `superseded` observations

*Written 2026-09-12 as the resume point for the next round of work. **Built the
same day.** Decisions are confirmed in §3.1, and what was built, with its limits,
is in `phase57-evidence-and-capture.md` §0.21. Background is §0.20 of that doc,
which built the offline re-grade pass and introduced the state.*

**Gates after the build:** pytest 2839 passed / 5 skipped. **At hand-off:** pytest 2816 passed / 5 skipped (pre-existing
missing-simulation skips), `ruff check` clean, `dev verify-contracts` OK. All of
phase 57 is uncommitted; the operator commits.

---

## 1. The problem

`chainsmith dev regrade <scan_id> --apply` marks a placeholder row
(`ungraded` / `grading_failed`) as `grading_state = "superseded"` when its
candidate now grades under different ids, and inserts the verdict rows that
replace it. Rows are never deleted (chains store observation ids; §2 says
nothing subtracts).

Nothing downstream knows the state exists. Every consumer reads every row, so
after an `--apply`:

- **Severity counts and risk are double-counted.** The placeholder (at its
  provisional severity) and its successor are both counted.
- **The placeholder is labelled "ungraded".** Reports test `!= "graded"`, so a
  superseded row lands in the "N observation(s) ungraded" note and prints
  `Grading: superseded (provisional severity)`.
- **Scan comparison and trends see a phantom finding.** The placeholder has its
  own fingerprint (its title is `"Ungraded: <subject> on <host>"`), so it can be
  counted new/recurring, and "resolved" in the next scan.
- **Chains, triage, adjudication and chat are fed the duplicate.**

## 2. Do not copy the suppression precedent as-is

§2 suppression is the obvious model (`app/lib/observations.py`:
`SUPPRESSED_STATUSES`, `partition_by_verdict`, `suppression_note`; used in
`app/reports.py:180`, `:301`, `app/engine/triage.py:279`,
`app/engine/adjudication.py:163`). But **suppressed rows stay in severity counts
and risk** (`_count_by_severity` at `reports.py:116` counts everything); they are
only marked. That is right for suppression, where the row is the only copy of
the finding. It is **wrong for superseded**: a superseded row *always* has a
successor row (or a re-grade that produced no verdict), so counting it counts the
same subject twice. Borrow the *stated, not silent* half of the precedent (a
count note and a visible listing), not the counting half.

## 3. Decisions to confirm at the start of the round

The recommendations are mine. Confirm or change each one before writing code.

| # | Question | Recommendation |
|---|---|---|
| S-1 | Where does the filter live? | **A repository default plus a shared helper.** `ObservationRepository.get_observations(..., include_superseded=False)` and `get_observations_by_host` likewise, so every consumer is fixed at one chokepoint. Opt in explicitly where the audit trail is wanted. Add `partition_by_grading()` / `supersession_note()` beside the suppression helpers for the report notes |
| S-2 | Do superseded rows count toward severity totals and risk? | **No** (see §2). Excluded everywhere counts are computed |
| S-3 | Are they listed in reports? | **Technical report (md/html/json): a count note plus a "Superseded by re-grade" appendix** naming each row's successors (already in `grading_reasoning`). **Executive / compliance: the count note only. CSV / SARIF: excluded** (SARIF `results` are findings) |
| S-4 | What do API routes return by default? | **Exclude by default, with an `include_superseded` query parameter.** The WebUI counts severity client-side (`static/scan.html:804`, `static/js/viz/viz-common.js:171`, `host-table.js:64,96`, `benchmark.js:36`), so an API default fixes those without JS changes |
| S-5 | `ObservationStatusHistory` is computed at scan completion, so rows computed before a re-grade are stale. What happens to them? | **Open; decide at the start.** Option A: `regrade --apply` recomputes `compute_observation_statuses` for the scan. Option B: document that comparisons reflect the scan as first recorded. A is more correct, but it rewrites history rows other scans' comparisons may have read |
| S-6 | Chains built before a re-grade name the placeholder's id | **Leave the chain rows alone.** When rendering a chain's observation list, resolve a superseded id to its successors. Do not rebuild chains automatically |

### 3.1 Confirmed 2026-09-12

The operator accepted S-1, S-2, S-3, S-4 and S-6 as recommended. **S-5 = cascade
recompute:** `regrade --apply` deletes the `ObservationStatusHistory` and
`ScanComparison` rows for the re-graded scan **and every later complete scan of
the same target**, then recomputes them in chronological order. History is data
rebuilt from observation rows and check logs, so rewriting it loses nothing.

Found while deciding S-5 (these block the cascade, so fix them as part of it):

- `compute_observation_statuses` is **not idempotent**: it appends history rows
  and a `ScanComparison` without clearing earlier ones.
- Its previous-scan lookup (`repositories.py:941`) takes the most recent *other*
  complete scan with **no `started_at <` bound**. That is correct only at scan
  completion. Rerun on an older scan, it pairs the scan with a later one.
- Its `previously_resolved` query reads history for the fingerprint across
  **all** scans, including later ones. The cascade must clear later scans'
  history before recomputing (or bound the query to earlier scans).
- `compare_scans` reads the cached `ScanComparison` and discards it, so it is
  always computed live. The repository filter alone fixes it.

## 4. Traps found while scoping

- **A SQL NULL trap.** `grading_state` is nullable, and rows from before 57.3
  hold NULL. `ObservationRecord.grading_state != "superseded"` **drops NULL
  rows** in SQL. Use
  `or_(ObservationRecord.grading_state.is_(None), ObservationRecord.grading_state != "superseded")`.
  Add a test with a NULL-state row.
- **The misclassification is its own bug.** `reports.py:185`, `:252-254` and
  `:302-304` classify with `!= "graded"`. Replace that with an explicit placeholder set
  (`ungraded`, `grading_failed`). `app/grading/regrade.py` already defines
  `_PLACEHOLDER_STATES`; promote it to a shared constant (in
  `app/grading/models.py` or `app/lib/observations.py`) instead of defining it
  twice.
- **The targeted export can pick the placeholder.** `generate_targeted_export`
  (`reports.py:1806-1865`) selects the most recent row per fingerprint
  with a raw `select`, bypassing the repository filter.
- **Callers that must keep reading superseded rows:** `ObservationRepository.get_records`
  (the re-grade diffs against it; it already reads raw), and the scratch import
  in `app/cli.py:2094`, which dedupes against existing rows. If it stops seeing
  superseded rows, it re-imports them.

## 5. Consumer inventory

**Repository (raw SQL that bypasses `get_observations`)**
- `ObservationRepository.get_observations`, `get_observations_by_host`: `app/db/repositories.py` (the chokepoint, S-1)
- `ComparisonRepository.compute_observation_statuses`: fingerprint queries at `repositories.py:954`, `:1004`, `:1011`, `:1020`, `:1031`
- `ComparisonRepository.compare_scans`: check it for the same pattern
- `TrendRepository._build_single_point`: severity/suite/fingerprint select at `repositories.py:1426`
- Trend MTTR `fp_severity`: `repositories.py:1588`

**Reports (`app/reports.py`)**
- technical `generate_technical_report` `:93` → counts/risk `:116-117`, markdown notes `:180-191`, per-row grading line `:252-254`, JSON `:289-307`, HTML `:678`, SARIF `:1659`, CSV `_observations_csv`
- delta `generate_delta_report` `:314` (counts both scans `:334-337`)
- executive `generate_executive_report` `:825` (plus previous-scan counts `:869-870`)
- compliance `generate_compliance_report` `:1060` (`:1082`)
- trend `generate_trend_report` `:1308` (through `TrendRepository`)
- targeted export `generate_targeted_export` `:1806` (raw select, §4)

**Routes:** `app/routes/scan_history.py:133`, `:150`, `:168`, `:428`;
`app/routes/observations.py:51`, `:64`, `:80`, `:104`; `app/routes/compliance.py:149`;
`app/routes/chains.py:52`, `:124`, `:160`; `app/routes/adjudication.py:51`

**Engine:** `app/engine/triage.py:190`, `app/engine/adjudication.py:56`,
`app/engine/chains.py:844`, `app/engine/chat.py:646`, `:763`, `:861`

**Clients of the API (fixed by S-4, verify only):** `app/cli.py:409`,
`app/dev/scan_diff.py:49`, and the WebUI files listed in S-4.

## 6. Suggested order

1. Shared constants and helpers (placeholder set, `is_superseded`,
   `partition_by_grading`, `supersession_note`), with unit tests.
2. Repository filter with the NULL-safe predicate, and the `include_superseded`
   parameter, with DB tests including a NULL-state row.
3. Fix the `!= "graded"` misclassification in `reports.py`.
4. Reports: counts/risk exclusion, notes, the technical appendix, CSV/SARIF exclusion,
   and the targeted-export raw select.
5. Comparison and trend raw SQL; then S-5, whichever way it was decided.
6. Routes: the `include_superseded` query parameter; chain rendering (S-6).
7. Docs: phase-57 doc (new §0.21, and remove the §0.20 "Reports do not yet
   filter" limit), `docs/vocabulary.md` (state is excluded from counts), memory.

## 7. Tests to write

- A report over a scan with an applied re-grade (placeholder superseded plus successor
  inserted): severity counts and risk equal the counts with the placeholder
  removed; the superseded note and appendix are present; the row is not in the
  ungraded note; CSV/SARIF omit it.
- `get_observations` excludes superseded rows by default, includes them with the flag, and
  keeps NULL-state rows either way.
- Comparison: a superseded placeholder's fingerprint is neither new nor resolved.
- Trend data point totals exclude superseded rows.
- The scratch import still dedupes against superseded rows.
- A good fixture path: build the scan with `tests/grading/test_regrade.py`'s
  `FakeCheck` plus `apply_regrade`, rather than hand-writing rows. It then stays
  honest if the re-grade changes.

## 8. Out of scope for this round

- An API/WebUI surface for running a re-grade (a CLI-only decision, §0.20).
- Recording check config for re-grade fidelity (§0.20 limit).
- D-21 measurement, O-4 swarm capture, retention, 57.5 encryption.
