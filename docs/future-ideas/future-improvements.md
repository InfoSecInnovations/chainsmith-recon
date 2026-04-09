# Future Improvements

General backlog of deferred enhancements that don't warrant their own
phase doc yet. Items here are candidates for inclusion in future phases
or for ad-hoc implementation when the relevant area is being touched.

---

## Prompt Router

### Routing accuracy tracking
Track classification decisions over time (route method, target agent,
operator behavior after routing) to identify weak keyword patterns and
improve the LLM classification prompt. Deferred from Phase 34 — the
router needs real usage data before this is valuable.

### Prompt expansion
Expand terse operator input into well-formed prompts for the target
agent (e.g., "is this bad?" → "Re-verify observation {id} and assess
exploitability"). Deferred from Phase 34 — revisit once the chat
interface (Phase 35) reveals whether operators need this or whether
keyword routing is sufficient on its own.
