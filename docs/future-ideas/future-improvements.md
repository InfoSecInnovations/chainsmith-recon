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
