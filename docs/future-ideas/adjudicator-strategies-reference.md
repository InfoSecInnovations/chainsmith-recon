# Adjudicator Strategies Reference

Archived reference for the four adjudication strategies that existed prior to
simplification (Phase 27, item 9). The agent now uses **evidence_rubric** only.
This document preserves the designs for potential future revisit.


## Active Strategy

### Evidence Rubric

Single LLM call. Maps observation evidence to a structured scoring rubric,
producing deterministic and comparable results.

**How it works:**
1. Score five factors (0.0-1.0 each): exploitability, impact,
   reproducibility, asset_criticality, exposure.
2. Average the scores.
3. Map to severity: >= 0.8 critical, >= 0.6 high, >= 0.4 medium,
   >= 0.2 low, < 0.2 info.

**Strengths:**
- Most deterministic — same evidence produces similar scores across runs.
- Cheapest (1 LLM call).
- Scores are individually inspectable — easy to understand *why* a
  severity was assigned.
- Factors map cleanly to CVSS concepts, familiar to security practitioners.

**Weaknesses:**
- Less nuanced for edge cases where context matters more than factors.
- Relies on the LLM to honestly score rather than argue a position.


## Retired Strategies

### Structured Challenge

Single LLM call, devil's advocate approach.

**How it works:**
1. Present the observation and ask the LLM to argue why the current
   severity might be wrong (too high or too low).
2. After arguing, render a final severity decision with confidence.

**Strengths:**
- Cheap (1 LLM call).
- Forces consideration of counterarguments.

**Weaknesses:**
- Free-form reasoning makes outputs harder to compare across observations.
- The "argue then decide" pattern can lead to the LLM anchoring on its
  own devil's advocate argument.

**When to revisit:** If evidence_rubric proves too rigid for observations
where environmental context outweighs raw technical factors.


### Adversarial Debate

Three LLM calls: prosecutor, defender, judge.

**How it works:**
1. **Prosecutor** argues severity should be maintained or raised.
2. **Defender** argues severity should be lowered.
3. **Judge** weighs both arguments and renders a verdict.

**Strengths:**
- Most thorough — surfaces arguments from both sides.
- Judge sees the strongest case for each position before deciding.

**Weaknesses:**
- 3x the cost and latency of single-call approaches.
- Prosecutor and defender can produce weak arguments on clear-cut cases,
  adding noise without value.
- Duplicated parsing/error-handling across three calls.

**When to revisit:** If high/critical observations need more rigorous
review and the cost is justified (e.g., pre-report final review pass).


### Auto (Tiered Dispatch)

Meta-strategy that selected an approach based on observation severity:
- Critical/High -> adversarial_debate
- Medium -> evidence_rubric
- Low/Info -> structured_challenge

**Rationale:** Spend more LLM budget on higher-severity observations where
the stakes of a wrong rating are higher.

**When to revisit:** If multiple strategies are re-added, auto dispatch
is the natural default. The tiering logic was sound — the issue was
shipping four strategies before validating any of them.


## Shared Infrastructure

All strategies share:
- `_format_context()` — builds the prompt string from observation +
  operator asset context.
- `_match_asset_context()` — matches observation targets to operator-declared
  asset domains (supports wildcards).
- `_fallback_result()` — returns original severity upheld at 0.0
  confidence when LLM call fails.
- `_clean_json()` — strips markdown fences from LLM output.

The shared parsing (`_parse_single_response`) was used by both
structured_challenge and adversarial_debate (same output schema). The
evidence_rubric has its own parser (`_parse_rubric_response`) due to the
scores object.
