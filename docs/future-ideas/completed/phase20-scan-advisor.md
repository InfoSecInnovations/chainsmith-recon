# Phase 20 — Scan Advisor

Optional, user-enabled agent that sits alongside the deterministic check engine.
Disabled by default. The advisor never runs checks — it only recommends.

## Core Responsibilities

### Pre-Scan
- Review config, scope, seed URLs for misconfigurations or gaps
- Suggest suite selection based on target type (cloud AI app, internal lab, etc.)
- Recommend forbidden_techniques based on rules of engagement
- Flag contradictory scope definitions

### Post-Scan (Phase 1 — build this first)
- Gap analysis: identify checks that could have run with better inputs
- Flag partial results (e.g., service probe timed out on N hosts)
- Suggest follow-up scans with reasons
- Cross-reference findings against the full check registry for missing coverage

### Between-Iterations (Phase 2 — future interactive mode)
- Pause check launcher between iterations
- Present real-time suggestions as context builds up
- Requires callback/pause mechanism in CheckLauncher

## Key Design Principles

1. **No precondition bypassing.** The dependency graph is correct. Instead:
   - **Context seeding** — inject known-good data the entry checks missed
   - **Gap detection** — flag where partial results left coverage holes
   - **Alternative fulfillment** — recognize when operator-provided data satisfies a check's intent
2. **Operator decides.** Advisor presents recommendations; user approves or dismisses.
3. **Speculative probing is explicit.** Suggestions like "probe common AI ports even though enumeration found nothing" are clearly labeled as outside the deterministic model.

## Recommendation Object

```
ScanAdvisorRecommendation:
  check_name: str
  reason: str           # human-readable explanation
  context_injection: dict  # data to seed if approved
  confidence: high | medium | low
  category: gap_analysis | config_suggestion | context_seed | speculative
```

## Configuration

```yaml
scan_advisor:
  enabled: false
  mode: post_scan           # post_scan (phase 1) or between_iterations (phase 2)
  auto_seed_urls: false     # allow advisor to suggest context injection
  require_approval: true    # user must approve each recommendation
```

## Open Questions

- **Intelligence source:** Pure rule-based, LLM-assisted, or both? Rules-first with optional LLM for reasoning about target nature is the current lean.
- **Cross-scan persistence:** Should the advisor remember what it suggested on previous scans of the same target and whether those suggestions were useful?
- **Tutor mode:** In scenario/training mode, the advisor could compare what ran vs. what the scenario expected, guiding students toward coverage gaps. May be its own feature but architecturally falls out naturally.
