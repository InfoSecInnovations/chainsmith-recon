# Phase 21: Adjudicator Agent — Risk Criticality Debate

## Overview

A new agent that challenges and debates the risk criticality of findings and
attack chains. The current pipeline (Scout -> Verifier -> Chainsmith) validates
whether findings *exist* but never questions whether the assigned severity is
*accurate*. The Adjudicator fills that gap by introducing adversarial reasoning
about risk ratings.

## Motivation

- A verified finding is not necessarily an exploitable one.
- Severity labels assigned by Scout are static and context-free.
- Chain severity multipliers (from `attack_patterns.json`) are pattern-based
  and don't account for target-specific context (e.g., internal-only services,
  VPN-protected assets).
- Operators need defensible risk ratings, not just raw scanner output.

## Pipeline Placement

### Phase 21a — Post-Verifier, pre-Chainsmith (MVP)

Adjudicate individual findings before chains are built. Chains then inherit
more accurate base severities. This is the initial implementation target.

### Phase 21b — Post-chain (future sub-phase)

Adjudicate the chain's *combined* severity as a whole. A medium + medium chain
might not warrant a 2.0x multiplier in context. Chain-level adjudication does
**not** re-litigate individual findings — it evaluates only the chain's
aggregate risk in context. This avoids infinite re-debate of findings that
were already adjudicated in Phase 21a.

## What the Adjudicator Debates

- **Severity accuracy** — Is this really critical, or medium given the target
  context? (e.g., missing security headers on an internal-only service.)
- **Exploitability** — Verified != exploitable. A finding can be real but
  impractical to exploit given attack complexity, required privileges, etc.
- **Chain plausibility** — The pattern matcher chains findings with 2+ keyword
  overlaps, but are those chains realistic attack paths?
- **Business context** — If scoping data includes asset criticality, the
  Adjudicator weighs that into the final rating.

## Implementation Approaches

All three approaches are implemented within a single `AdjudicatorAgent` class,
selectable via the `approach` parameter. This follows the existing agent pattern
(single class with `event_callback`, `emit()`, LLM client via `get_llm_client()`).

### Approach 1: Adversarial Debate (`adversarial_debate`) — 3 LLM calls
One call argues the severity should be higher, one argues lower, then a judge
call resolves. Most thorough but most expensive.

### Approach 2: Structured Challenge (`structured_challenge`) — 1 LLM call
Prompt the LLM as devil's advocate to argue *against* the current severity
rating. If the argument holds, downgrade; if it doesn't, confirm. Cheaper,
still effective.

### Approach 3: Evidence-Based Rubric (`evidence_rubric`) — hybrid
Build a CVSS-like rubric (attack vector, complexity, privileges required,
impact scope) and have the LLM map finding evidence to rubric factors rather
than free-form debating. More deterministic and reproducible.

### Approach Selection

The approach is configurable at three levels (highest priority wins):

1. **Per-invocation** — API query parameter (`adjudication_approach=...`) or
   CLI flag (`--adjudication ...`)
2. **Per-installation** — `~/.chainsmith/preferences.yaml`
3. **Default** — `auto` (tiered by severity, see Cost Management below)

## Output Model

Rather than overwriting Scout's original severity, the Adjudicator should
produce a separate `adjudicated_risk` field:

```
adjudicated_risk:
  original_severity: high
  adjudicated_severity: medium
  confidence: 0.85
  rationale: "Finding is valid but requires local network access..."
  factors:
    attack_vector: local
    complexity: high
    privileges_required: low
    impact: medium
```

This preserves the original assessment while adding the Adjudicator's opinion.

## Operator Context

The Adjudicator consumes operator-provided asset context to inform its debate.
It is **read-only** — it cannot alter scope, findings, or Guardian rules. It
only produces `adjudicated_risk` annotations alongside the originals.

### Context File

Operator context is declared in `~/.chainsmith/adjudicator_context.yaml`:

```yaml
asset_context:
  - domain: "api.example.com"
    exposure: internet-facing      # internet-facing | vpn-only | internal
    criticality: high              # critical | high | medium | low
    notes: "Production API, handles PII"
  - domain: "internal-tools.example.local"
    exposure: vpn-only
    criticality: low

defaults:
  exposure: unknown
  criticality: medium
```

The Adjudicator also receives scope info from the Guardian/ScopeDefinition for
additional context (in-scope domains, port profiles, etc.) but cannot modify it.

### Design Note

This context file lives in `~/.chainsmith/` — the installation-specific config
directory. Updates to Chainsmith should never overwrite files in this directory.
This pattern is consistent with existing `preferences.yaml`, `scenarios/`, and
`customizations/` in the same location.

## Cost Management

Adversarial debate is expensive. The `auto` approach (default) uses a tiered
strategy to keep costs reasonable:

| Finding Severity | Adjudication Level            |
|------------------|-------------------------------|
| Critical / High  | Full adversarial debate       |
| Medium           | Structured challenge (single) |
| Low / Info       | Skip or rubric-only           |

When a specific approach is selected via CLI/API/preferences, it overrides
this tiering and applies uniformly to all findings.

## New Events

```
ADJUDICATION_START
ADJUDICATION_COMPLETE
SEVERITY_UPHELD
SEVERITY_ADJUSTED
```

## Future Features

- **External threat intelligence** — EPSS scores, known-exploited-vulnerabilities
  catalog (KEV) to inform adjudication. Marketed as a future premium feature.
- **Learning loop** — adjudication results feed back into attack pattern weights
  over time.
- **Compliance/audit reporting** — persisting adjudication rationales for
  regulatory use.

## Open Questions

- Should adjudication results feed back into attack pattern weights over time
  (learning loop)?
- Is there value in persisting adjudication rationales for compliance/audit
  reporting?

## Dependencies

- Phase 1-3 persistence (complete) — adjudication results need storage
- Verifier agent — Adjudicator operates on verified findings only
- Attack chain builder — for Phase 21b chain-level adjudication

## LLM Integration

All LLM calls are handled via the existing `get_llm_client()` path, resolved
from `--profile` in `chainsmith.sh`. A `model_adjudicator` field will be added
to `LiteLLMConfig` in `app/config.py` for per-agent model overrides, consistent
with `model_scout`, `model_verifier`, and `model_chainsmith`.
