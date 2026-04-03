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

**Option A — Post-Verifier, pre-Chainsmith:**
Adjudicate individual findings before chains are built. Chains then inherit
more accurate base severities.

**Option B — Post-chain:**
Adjudicate the chain's *combined* severity. A medium + medium chain might not
warrant a 2.0x multiplier in context.

**Option C — Both (tiered):**
Quick individual-finding adjudication for all findings, deeper chain-level
debate only for high+ severity chains. Balances cost and thoroughness.

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

### Approach 1: Adversarial Debate (two LLM calls)
One call argues the severity should be higher, one argues lower, then a judge
call resolves. Most thorough but most expensive (3 LLM calls per adjudication).

### Approach 2: Structured Challenge (single LLM call)
Prompt the LLM as devil's advocate to argue *against* the current severity
rating. If the argument holds, downgrade; if it doesn't, confirm. Cheaper,
still effective.

### Approach 3: Evidence-Based Rubric (hybrid)
Build a CVSS-like rubric (attack vector, complexity, privileges required,
impact scope) and have the LLM map finding evidence to rubric factors rather
than free-form debating. More deterministic and reproducible.

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

## Operator Interaction (Optional)

The Adjudicator could optionally accept operator context to inform its debate:

- "This API is internet-facing" -> raises severity weight
- "This service is behind a VPN" -> lowers exploitability
- "This is a production database" -> raises impact

This could integrate with the existing scoping conversation in Chainsmith.

## Cost Management

Adversarial debate is expensive. A tiered strategy keeps costs reasonable:

| Finding Severity | Adjudication Level            |
|------------------|-------------------------------|
| Critical / High  | Full adversarial debate       |
| Medium           | Structured challenge (single) |
| Low / Info       | Skip or rubric-only           |

## New Events

```
ADJUDICATION_START
ADJUDICATION_COMPLETE
SEVERITY_UPHELD
SEVERITY_ADJUSTED
```

## Open Questions

- Should the Adjudicator have access to external threat intelligence (e.g.,
  EPSS scores, known-exploited-vulnerabilities catalog) to inform its debate?
- Should adjudication results feed back into attack pattern weights over time
  (learning loop)?
- Is there value in persisting adjudication rationales for compliance/audit
  reporting?

## Dependencies

- Phase 1-3 persistence (complete) — adjudication results need storage
- Verifier agent — Adjudicator operates on verified findings only
- Attack chain builder — for chain-level adjudication
