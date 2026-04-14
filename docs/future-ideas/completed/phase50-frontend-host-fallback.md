# Phase 50: Move Frontend Host-Fallback Logic into the API

## Overview

Remove the `f.host || f.target_url || 'unknown'` host-derivation
fallback that is currently duplicated across the WebUI visualization
scripts. After Phase 45 lands `target_host` on `Observation`, the API
should be the single source of truth for the observation host, and
the frontend should be a thin presentation layer.

## Motivation

Surfaced while reviewing Phase 45 (April 2026). The user's stated
position: **"the WebUI is only a wrapper for the API."** Auditing
the frontend revealed one consistent violation of that principle:

Five viz files each re-derive the host field locally:

- `static/js/viz/coverage.js:63`
- `static/js/viz/benchmark.js:20`
- `static/js/viz/heatmap.js:20`
- `static/js/viz/timeline.js:20`
- `static/js/viz/treemap.js:22`

All five contain the same logic:

```js
var rawHost = f.host || f.target_url || 'unknown';
```

`static/js/viz/viz-common.js:142` additionally parses a hostname from
a URL via `new URL(name).hostname`.

This is business logic (choosing which identifier best describes the
observation's host) that belongs server-side. It also undermines the
Phase 45 guarantee: once the API reliably populates `target_host`, the
fallback is dead code that can mask future regressions — if the API
ever stops setting the field, the frontend silently papers over it.

## Target Changes

### API layer (`app/routes/observations.py` + any viz/report endpoints)

- Guarantee `target_host` is populated on every outgoing observation.
- If the stored `Observation` has `target_host=None` (legacy data),
  compute it at serialization time by parsing `target_url`. This is
  the one place the fallback is allowed to live.
- Apply the same guarantee to any viz-feeding endpoints that emit
  per-finding host data (coverage, benchmark, heatmap, timeline,
  treemap payloads).

### Frontend viz files

- Replace `var rawHost = f.host || f.target_url || 'unknown';` with
  `var rawHost = f.target_host;` in all five files.
- Remove `new URL(name).hostname` fallback from `viz-common.js` if
  no longer referenced.
- If `target_host` is unexpectedly missing, render the observation
  under an explicit `'unknown'` bucket rather than silently deriving.
  Missing host is now an API bug, not a display concern.

## Dependencies

Blocked by Phase 45 — the `target_host` field must exist and be
reliably populated by the check layer first.

## Test Plan

- Unit: API serializer returns `target_host` for legacy observations
  that only have `target_url`.
- Unit: API serializer returns `target_host` unchanged when already
  set by the check.
- Manual: re-run fakobanko scenario, open each viz page, confirm
  hosts render correctly with the frontend fallback removed.

## Out of Scope

- Larger WebUI → API audit. This phase is specifically the host-field
  duplication. If other business logic is found in the frontend
  during implementation, file follow-up phases rather than expanding
  scope here.
- Renaming `target_url` / `target_service`.
