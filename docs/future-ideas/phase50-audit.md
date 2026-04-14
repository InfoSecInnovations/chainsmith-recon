# Phase 50 — UTC Datetime Hygiene: Audit Report

Audit produced 2026-04-14 per `phase50-utc-datetime-hygiene.md`. Lists
every offender with category. Fix pass consumes this file.

## Current state summary

Partial migration is already in progress. Files that already import
`from datetime import UTC, datetime` and use `datetime.now(UTC)`:
`agents/chainsmith.py`, `engine/chat.py`, `engine/chains.py`,
`routes/chat.py`, `db/repositories.py`, `db/models.py`, `reports.py`,
`swarm/models.py`, `swarm/auth.py`, `swarm/coordinator.py`,
`checks/network/whois_lookup.py`, `checks/simulator/simulated_check.py`,
`scenario_services/common/config.py`. Offenders below are files that
still need conversion.

## Categories

- **N** — naive construction (`datetime.utcnow()` or bare
  `datetime.now()`)
- **P** — parse that strips offset (fromisoformat with `.replace(...)`
  cleanup, or strptime without tz)
- **B** — missing boundary conversion (external input stored/compared
  naive)
- **D** — display-layer leak (ISO emitted without offset, or naive
  ISO stored)

A single line often carries both N and D (e.g. `utcnow().isoformat()`
emits a naive ISO string).

## Offenders in `app/` (production code — must fix)

### Critical — the motivating bug

- `app/proof_of_scope.py:95` — **N** `datetime.utcnow()` for `now`.
- `app/proof_of_scope.py:98-99` — **P** `fromisoformat(self.start.replace("Z","+00:00").replace("+00:00",""))` strips offset entirely, making comparison wrong by the stored offset.
- `app/proof_of_scope.py:105` — **P** same pattern on `self.end`.
- `app/proof_of_scope.py:188,211,273,348` — **N/D** `datetime.utcnow().isoformat() + "Z"` on `ScopeViolation.timestamp` and `ComplianceReport.generated_at`. The `+ "Z"` lies: the value is naive UTC-ish, not verified UTC.

### Check / engine layer

- `app/checks/base.py:315,334` — **N** `started`, `result.completed_at`.
- `app/checks/network/tls_analysis.py:18` — uses `import datetime` (module form); lines 242, 327, 328 use `datetime.datetime.strptime(...)` / `fromisoformat(not_after)` / `datetime.datetime.utcnow()`. **N** + **P** (strptime without tz).
- `app/checks/network/whois_lookup.py:528` — **P** `datetime.strptime(created_str, fmt)` returns naive; later compared against `datetime.now(UTC)` — same file mixes both.
- `app/engine/triage.py:75` — **P** `fromisoformat(answered_at.replace("Z","+00:00"))` — this one is actually OK (Z→+00:00 preserves offset); classify as acceptable.
- `app/engine/triage.py:128` — **N/D** `datetime.utcnow().isoformat() + "Z"`.
- `app/lib/observations.py:150` — **N** `discovered_at=datetime.utcnow()`.

### Tools

- `app/tools/verify_cve.py:71,133,179,220` — **N/D**.
- `app/tools/robots_fetch.py:33,134` — **N/D**.
- `app/tools/probe_chatbot.py:33,49,56,134,204` — **N/D** (including duration measurement start/end — naive diff is fine but use aware for consistency).
- `app/tools/port_scan.py:37,96` — **N/D**.
- `app/tools/header_grab.py:32,144` — **N/D**.
- `app/tools/extract_prompt.py:86,209` — **N/D**.

### Agents

- `app/agents/verifier.py:274` — **N** `f.verified_at = datetime.utcnow()`.
- `app/agents/chainsmith.py:737` — **N** `identified_at=datetime.utcnow()` (file already imports `UTC`, just missed this call site).

### Routes / display

- `app/routes/scope.py:75,194` — **N/D** `outside_window_acknowledged_at` and `current_time` response field.
- `app/routes/compliance.py:123` — **N/D** `generated_at`.
- `app/cli_formatters.py:92,110` — **N/D** report `generated` fields.

### DB repositories

- `app/db/repositories.py:1007,1013` — **P** `datetime.fromisoformat(since)` / `...(until)` — if callers pass naive ISO, this stays naive. Needs explicit tz handling at boundary (assume/require UTC).

### Scenario services under `app/`

- `app/scenario_services/banking/tools.py:150,163,169` — **N/D** (service-layer, emitted to HTTP clients — likely lower priority but rule applies).
- `app/scenario_services/banking/chatbot.py:109,294` — **N** (conversation id and rate-limit timestamp).

## Offenders in `tests/`

- `tests/scanning/test_proof_of_scope.py:120,127,135,142,149,150,159` — **N** test fixtures using `datetime.utcnow()`. Fix by freezing time or constructing aware UTC instants.
- `tests/checks/test_network_tls.py:29,33` — **N** cert date fixtures.

## Offenders in `scenarios/` (out-of-tree demo services)

These run as separate demo containers, not under `app/`. Rule still
applies but they are lowest priority and the lint rule need not cover
them (scope rule to `app/` + `tests/` per deliverable #3).

- `scenarios/fakobanko/config.py:263,292`
- `scenarios/fakobanko/tools.py:133,147,153`
- `scenarios/fakobanko/chatbot.py:69,212`
- `scenarios/demo-domain/services/{agent,cache,rag,api}.py` — multiple
- `scenarios/demo-domain/services/cache.py:211` — **P** `fromisoformat(...replace("Z","+00:00"))` — OK pattern, keep as-is.
- `scenarios/demo-domain/demo_domain/{tools,config}.py` — multiple

## Other

- `range/start-range.sh:209` — shell-embedded Python using `datetime.now()`.
- `docs/plan-third-party-api-auth.md:226,233` — sample code in a plan doc; fix when that plan is implemented, not now.

## UI (`static/`)

Files using `new Date()` / `toLocaleString`: `static/scan-history.html`,
`static/reports.html`, `static/index.html`, `static/js/viz/viz-common.js`,
`static/js/viz/trend-charts.js`. These are the **display** layer — they
should receive UTC ISO strings from the API and render local. No
changes needed if the API side (fixed above) emits proper aware ISO.
Spot-check each during fix pass to confirm parse handles `+00:00`/`Z`.

## Fix-pass plan

1. Introduce `app/lib/timeutils.py` with:
   - `now_utc() -> datetime` returning `datetime.now(UTC)`.
   - `iso_utc(dt: datetime | None = None) -> str` emitting `...+00:00`.
   - `parse_iso_utc(s: str) -> datetime` — replace `Z` with `+00:00`, call `fromisoformat`, assert `tzinfo is not None`, convert to UTC.
   Use these consistently; avoid ad-hoc formatting.
2. Walk categories top-down (Critical → Engine → Tools → Agents → Routes → DB → Scenarios-under-app → Tests).
3. Fix `proof_of_scope.is_within_window` using `parse_iso_utc` for both bounds and `now_utc()` for current time. Delete the `.replace("+00:00","")` strip.
4. Enable ruff `DTZ` ruleset in `pyproject.toml` scoped via per-file-ignores so `scenarios/` and docs are excluded if needed. Run `ruff check app tests` to confirm no remaining offenders.
5. Add one-line note to `docs/vocabulary.md`: UTC internal, local at display.
6. Re-run tests; fix the two test files that rely on naive now.

## Out of scope / deferred

- `scenarios/` demo services (run as standalone, not scanned by our ruff rule).
- Doc code snippets (`docs/plan-third-party-api-auth.md`).
- UI localization audit beyond confirming current code parses offsets.
