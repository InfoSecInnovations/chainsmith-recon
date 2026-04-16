# Phase 52 — Remove Engagements Concept

**Status:** Design / pending implementation
**Depends on:** concurrent-scans-overhaul Phase F (ChatMessage now has `scan_id`, so `engagement_id` is no longer load-bearing anywhere useful).

---

## 1. Motivation

"Engagements" were introduced as a way to group scans together under a
named campaign with shared settings and a shared chat thread. In practice:

- The grouping is redundant with scan history filters (by target, by date
  range, by status).
- The concept is opaque to non-pentest users; "engagement" is pentest
  jargon.
- The feature carries architectural tax (FK columns on `scans`,
  `chat_messages`; dedicated routes; UI pages) for capability nobody uses.

The *time-window enforcement* that currently lives under "engagement
window" (Guardian gate that blocks scans outside the allowed hours) is
genuinely useful and stays — just under a clearer name: **scan window**.

## 2. Scope

### 2.1 Remove

- `Engagement` model and `engagements` table.
- `engagement_id` columns on `ChatMessage` and any other model referencing
  it (scans, etc.).
- Routes under `/api/v1/engagements/*`.
- Web UI: `engagements.html` and nav links to it.
- `state.engagement_id` and every reference (`routes/chat.py`, dispatcher,
  repo helpers, etc.).
- Engagement-scoped chat history (`get_history(engagement_id=...)`,
  `export_engagement_chat`).
- Tests for engagement CRUD and engagement-scoped chat.

### 2.2 Rename

- `engagement_window` / `EngagementWindow` → `scan_window` / `ScanWindow`
  across Guardian, config, API models, proof-of-scope settings, docs.
- UI labels: "Engagement window" → "Scan window".
- Keep Guardian's `check_engagement_window` method renamed to
  `check_scan_window`.

### 2.3 Keep intact

- All Guardian enforcement semantics (outside-window blocks, operator
  acknowledgment override).
- Scan history filtering (target, date range, status).
- Per-scan proof settings.

## 3. Phases

| Phase | Scope | Breaking? |
|---|---|---|
| 52.1 | Rename `engagement_window` → `scan_window` across code + docs (no behavior change). | API field name change |
| 52.2 | Remove `state.engagement_id` + route-level engagement plumbing (chat now uses `scan_id`). | Chat export endpoint removed |
| 52.3 | Drop `engagement_id` columns and the `engagements` table. Greenfield — no migration. | Schema change |
| 52.4 | Remove engagement routes, UI page, nav. | UI change |
| 52.5 | Sweep: docstrings, CLAUDE.md, future-ideas docs, scenario descriptions, test fixtures. | No |

## 4. Open questions

1. **Proof settings coupling.** `proof_settings.engagement_window` — is
   this purely a scan-window-in-disguise, or does it carry engagement
   identity too? Review during 52.1; expect it to be the former.
2. **Scenario configs.** Some scenarios reference engagement concepts in
   descriptive text (not data). Confirm they can be updated in 52.5.
3. **CLI / module API.** No current modules reference engagements, but
   confirm when module system lands.

## 5. Definition of done

- `git grep -i engagement` returns zero matches outside migration notes
  and phase-52 docs themselves.
- Scan window enforcement still blocks scans outside the configured
  hours; same behavior, new name.
- Chat history + export still work, scoped by `chat_session_id` and
  optionally by `scan_id`.
- Web UI has no broken links to removed pages.
- Test suite green.
