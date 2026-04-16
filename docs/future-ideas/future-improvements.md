# Future Improvements

General backlog of deferred enhancements that don't warrant their own
phase doc yet. Items here are candidates for inclusion in future phases
or for ad-hoc implementation when the relevant area is being touched.

---

## Prompt Router

### Routing accuracy tracking
Track classification decisions over time (route method, target component,
operator behavior after routing) to identify weak keyword patterns and
improve the LLM classification prompt. Deferred from Phase 34 — the
router needs real usage data before this is valuable.

---

## Operator Chat (Phase 35)

### Team / shared chat
Per-user SSE streams are the MVP model. A future enhancement should add
a shared team chat mode where multiple operators on the same engagement
can see each other's messages and agent responses. Requires: user
identity on messages, presence indicators, and conflict resolution if
two operators issue contradictory instructions to the same component.

### Chat history management for long engagements
Multi-day engagements can accumulate thousands of chat messages. Add
pruning, archival, and in-chat search capabilities. Candidates:
- Auto-archive messages older than N days (configurable per engagement)
- Full-text search within chat history
- Summary generation: agent-produced digest of key decisions and actions
  from the chat log
- Storage tiering: recent messages in SQLite, older messages compressed
  or moved to file-based archive

---

## Prompt Router

### Prompt expansion
Expand terse operator input into well-formed prompts for the target
agent (e.g., "is this bad?" → "Re-verify observation {id} and assess
exploitability"). Deferred from Phase 34 — revisit once the chat
interface (Phase 35) reveals whether operators need this or whether
keyword routing is sufficient on its own.

---

## Database Resilience

### Scratch-space fallback alert
When the database is unreachable and Chainsmith falls back to writing
data to the scratch space, surface a visible alert to the operator so
the condition is not silently swallowed. The alert should:
- Appear in the UI (e.g., banner or toast notification)
- State which write failed and where the data was persisted instead
- Persist until the operator acknowledges it or the DB connection recovers
- Optionally log the event so post-engagement review can identify
  reliability patterns

---

## AttackChainProofAdvisor (from Phase 22)

Phase 22 introduces CheckProofAdvisor for per-finding reproduction guidance.
A natural extension is chain-level proof guidance — ordered, multi-step
reproduction walkthroughs for entire attack chains.

### What it would do

- Generate ordered reproduction steps across multiple linked findings
- Handle step dependencies (e.g., "exploit F-002 first to get the session
  token needed to reproduce F-007")
- Produce a single coherent proof narrative for report inclusion
- Map prerequisite conditions between chain links

### Why it's deferred

Chain-level proof is meaningfully more complex than per-finding proof:
- Reproduction order matters and steps may depend on each other
- Prerequisite conditions between findings need to be modeled
- Whether this should be deterministic (Advisor) or LLM-powered (Agent) is
  an open question — the ordering and dependency reasoning may benefit from
  LLM capabilities

### When to revisit

After CheckProofAdvisor has real usage data and operators express a need for
chain-level proof guidance in their reports.

---

## Researcher Agent — Offline Mode Enhancements (from Phase 22)

Phase 22's Researcher agent supports a basic offline mode where tools return
cached/bundled data or "not available" responses. For air-gapped network
deployments, this should be expanded:

### Bundled vulnerability database

- Ship a periodically-updated snapshot of NVD data with Chainsmith releases
- Allow operators to import custom vulnerability feeds (vendor-specific, internal)
- Version and date-stamp bundled data so operators know how stale it is

### Cache-forward mode

- When running online, Researcher caches all fetched enrichment data locally
- Subsequent offline runs can use this cache for any previously-seen CVEs,
  products, or versions
- Cache is per-engagement, exportable for sharing across team members

### Manual enrichment import

- Operators can drop enrichment files (JSON/YAML) into a known directory
- Researcher consumes these as if they were API responses
- Useful when one team member has network access and another does not

### When to revisit

When Chainsmith is deployed in air-gapped environments and operators report
that the basic offline mode is insufficient

---

## Scan State Streaming (Phase 51)

### Strict event ordering
Phase 51 delivers events best-effort per scan. `observation_added` from
`ObservationWriter` can interleave with `check_completed` from the scanner
callback rather than strictly preceding it. Revisit if UI/consumers start
depending on strict per-check ordering — likely requires funnelling both
publish sites through a single ordered queue per check, or buffering
`check_completed` until its observations have drained.

### Dedicated `/api/v1/capabilities` endpoint
Phase 51 advertises streaming support via a `capabilities` field on
`GET /api/v1/scan`. Once a second feature flag needs advertisement, lift
this into a standalone `/api/v1/capabilities` endpoint so clients fetch
flags once at page load instead of reading them off a scan response.
