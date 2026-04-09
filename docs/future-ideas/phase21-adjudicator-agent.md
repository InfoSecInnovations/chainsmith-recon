# Phase 21: Adjudicator Agent — Risk Criticality Debate

## Overview

A new agent that challenges and debates the risk criticality of findings and
attack chains. The current pipeline (ScanAdvisor -> Verifier -> Chainsmith) validates
whether findings *exist* but never questions whether the assigned severity is
*accurate*. The Adjudicator fills that gap by introducing adversarial reasoning
about risk ratings.

## Motivation

- A verified finding is not necessarily an exploitable one.
- Severity labels assigned by ScanAdvisor are static and context-free.
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

Rather than overwriting ScanAdvisor's original severity, the Adjudicator should
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
It produces `adjudicated_risk` annotations alongside the originals and **can
override any prior severity assignment**, including those constrained by
Guardian rules. However, the Adjudicator's reasoning must be firmly grounded
in best practices as defined by disinterested third-party authorities:
**NIST**, **OWASP**, **SANS**, **IANS**, and **MITRE**. The Adjudicator is
not a vehicle for operator preference — it is an independent assessor that
applies established frameworks to produce defensible ratings.

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
| Low / Info       | Skip (unless user-triggered)  |

When a specific approach is selected via CLI/API/preferences, it overrides
this tiering and applies uniformly to all findings.

**Note on Low/Info findings:** The `auto` tier skips Low/Info findings because
individually they rarely warrant adjudication cost. However, a series of Low
findings that chain together may produce a High or Critical aggregate severity
via chain multipliers. Since Phase 21a runs before chaining, it cannot predict
which Lows will matter. Operators who suspect a cluster of Lows constitutes a
meaningful attack path can explicitly trigger adjudication for those findings
via CLI (`--adjudicate-finding F-xxx`) or API, bypassing the auto-tier skip.

## New Events

```
ADJUDICATION_START
ADJUDICATION_COMPLETE
SEVERITY_UPHELD
SEVERITY_ADJUSTED
```

## Adjudication Audit & Governance

Reclassifying vulnerability severity is a consequential action. A tool that
downgrades a Critical to a Medium without a defensible audit trail is a
liability, not a feature. This section defines the audit infrastructure
required to make adjudication decisions reviewable, reproducible, and
tamper-evident under a **three-line governance model** (as used in financial
services):

- **1st line** — the operator running Chainsmith (owns the scan, triggers
  adjudication)
- **2nd line** — risk/compliance oversight (reviews the audit trail
  independently, does not participate in the scan)
- **3rd line** — internal audit or external regulator/assessor (periodic
  independent assurance)

The audit trail is the primary artifact 2nd line uses to verify that
reclassifications were legitimate. If it can satisfy 2nd line review, it
should pass regulatory or insurance assessor scrutiny.

### Design Principles

1. **Self-contained** — a reviewer who was not present during the scan can
   reconstruct the full decision chain from the audit record alone, without
   access to the running system.
2. **Complete** — every input the LLM saw, every output it produced, every
   context that influenced the decision is captured.
3. **Independently verifiable** — 2nd line does not need to trust the
   operator's word about what happened. The record speaks for itself.
4. **Separation of custody** — tamper evidence comes from the audit data
   living in a system the 1st line operator does not control.

### Sealed Decision Records

Each adjudication produces a **sealed decision record** — a self-contained
audit unit capturing the complete decision context. One record per finding
per adjudication run.

```yaml
sealed_decision_record:
  # --- Identity ---
  record_id: "adr-20260404-a1b2c3"       # Unique, non-guessable
  scan_id: "scan-xyz-789"
  finding_id: "F-001"
  run_id: "adj-run-20260404-1"            # Groups all decisions from one invocation

  # --- Who & When ---
  triggered_by: "operator"                # operator | api_integration | scheduled
  trigger_source: "POST /api/v1/adjudicate"
  triggered_at: "2026-04-04T14:32:01Z"
  completed_at: "2026-04-04T14:32:08Z"

  # --- Approach Selection ---
  approach_requested: "auto"              # What the operator asked for
  approach_resolved: "adversarial_debate" # What actually ran (after auto-tiering)
  approach_override_reason: null          # Required if operator forced a non-default

  # --- Inputs (what the LLM saw) ---
  inputs:
    finding_snapshot:                      # Frozen copy of finding at adjudication time
      id: "F-001"
      title: "SQL Injection in login endpoint"
      severity: "critical"
      status: "verified"
      evidence: "..."
      verification_notes: "..."
    operator_context_matched:             # Which asset context entry matched
      domain: "api.example.com"
      exposure: "internet-facing"
      criticality: "high"
      notes: "Production API, handles PII"
      match_type: "exact"                 # exact | wildcard | default_fallback
    scope_context:                        # Relevant scope info provided to LLM
      in_scope_domains: ["api.example.com"]
      port_profile: "web_common"

  # --- LLM Interactions (complete prompt/response capture) ---
  llm_interactions:
    - step: "prosecution"                 # or "challenge", "rubric", "defense", "judge"
      model: "llm-provider/model-name"  # Resolved via LiteLLM profile
      prompt_hash: "sha256:abcdef..."     # Hash of full prompt
      prompt_text: "..."                  # Full prompt sent to LLM
      response_text: "..."               # Full raw response from LLM
      response_parsed:                    # Structured extraction from response
        argument: "..."
        severity_recommendation: "critical"
      latency_ms: 2340
      tokens_in: 1820
      tokens_out: 640
    - step: "defense"
      # ... same structure
    - step: "judge"
      # ... same structure

  # --- Decision Output ---
  decision:
    original_severity: "critical"
    adjudicated_severity: "medium"
    confidence: 0.85
    rationale: "Finding is valid but requires local network access..."
    factors:
      attack_vector: "local"
      complexity: "high"
      privileges_required: "low"
      impact: "medium"

  # --- Re-adjudication Context (if applicable) ---
  prior_adjudication:
    prior_record_id: "adr-20260401-x9y8z7"
    prior_adjudicated_severity: "high"
    prior_confidence: 0.72
    justification: "New asset context added — target confirmed VPN-only"
    delta:
      severity_change: "high -> medium"
      confidence_change: 0.72 -> 0.85

  # --- Integrity ---
  record_hash: "sha256:..."              # Hash of this record's contents
  prior_record_hash: "sha256:..."        # Hash of previous record in chain
  chain_position: 42                     # Monotonic sequence number
```

### Re-adjudication Controls

Re-adjudicating a previously adjudicated finding is permitted but tracked.
The tool does not judge whether the reason is valid — a human reviewer does.
The tool guarantees the justification exists and was captured **before**
re-adjudication ran.

**Requirements:**

- When adjudication is triggered and a finding already has an adjudication
  result (from a prior run in the same scan or from DB history), the API
  **must** require a `justification` field explaining why re-adjudication
  is warranted.
- The justification is stored in the sealed decision record's
  `prior_adjudication.justification` field.
- The prior decision is linked by `prior_record_id` and the severity/confidence
  delta is computed and stored automatically.
- The `GET /api/v1/adjudication/{finding_id}/history` endpoint (see Audit
  API below) returns the full chain of decisions for a finding, making
  repeated reclassification patterns visible to reviewers.

**Non-goals:**

- Automated plausibility checking of justifications. The nuance required
  to assess whether "new context added" is a legitimate reason to re-run
  is beyond what the tool should gate. This is a 2nd line human judgment.
- Blocking re-adjudication. The operator can always re-run — the audit
  trail ensures they can't do so silently.

### Integrity Chain

Sealed decision records are hash-linked into a chain for local integrity
verification. Each record includes a SHA-256 hash of its contents and the
hash of the previous record in the chain.

**What hash chains provide:**

- Detection of in-place record modification (a changed record breaks the
  chain from that point forward)
- Proof of sequence (records can't be reordered without detection)
- Detection of insertion (injecting a record breaks the chain)

**What hash chains do NOT provide:**

- Protection against wholesale deletion and reconstruction. An actor with
  full DB access can delete all records and rebuild a clean chain with
  fabricated data. Hash chains alone are insufficient tamper evidence
  against a determined insider.

**This is by design.** Local integrity is one layer. Tamper evidence comes
from separation of custody (see Event Forwarding below).

### Event Forwarding

The real tamper-evidence layer. Audit events are forwarded in real-time to
a system the 1st line operator does not control. The operator can destroy
their local DB, but the forwarded events are already in 2nd line's custody.

**Forwarding targets (configurable, multiple simultaneous):**

1. **Webhook** — HTTPS POST to a configured endpoint. Intended for SIEM
   ingestion, SOAR platforms, or a dedicated audit service. Payload is the
   sealed decision record (JSON).
2. **Syslog** — RFC 5424 structured syslog over TLS. For organizations with
   existing log aggregation infrastructure (Splunk, ELK, Graylog, etc.).

**Configuration** (`~/.chainsmith/preferences.yaml`):

```yaml
adjudicator:
  audit:
    forwarding:
      - type: webhook
        url: "https://siem.example.com/api/ingest/chainsmith"
        headers:
          Authorization: "Bearer ${CHAINSMITH_AUDIT_TOKEN}"
        retry:
          max_attempts: 3
          backoff_seconds: [1, 5, 15]
      - type: syslog
        host: "logcollector.internal"
        port: 6514
        protocol: "tcp+tls"
        facility: "auth"
        severity: "informational"
```

**Forwarding guarantees:**

- **At-least-once delivery** — failed forwards are queued locally and
  retried with exponential backoff. The queue persists across restarts.
- **Forward-before-complete** — the adjudication run does not report
  "complete" status until all audit records are either forwarded
  successfully or queued for retry. The operator sees adjudication as
  in-progress until the audit trail is secured.
- **Forwarding failure visibility** — if forwarding fails after all
  retries, the failure is logged locally, an event is emitted
  (`AUDIT_FORWARD_FAILED`), and the adjudication result is annotated
  with `audit_forwarding_status: "failed"`. This is visible in the
  API response and should be flagged by 2nd line review.

**Checkpoint signatures:**

Periodically (configurable, default: end of each adjudication run), a
checkpoint record is forwarded containing:

- Hash of the full chain state up to that point
- Count of records in the chain
- Timestamp

If the local chain diverges from the last checkpoint 2nd line received,
the data has been altered. This catches deletions that a hash chain alone
cannot.

### Audit API Endpoints

Read-only endpoints designed for 2nd line reviewers and export tooling.
These do not modify any data.

#### `GET /api/v1/audit/adjudication/{scan_id}`

Full audit trail for a scan. Returns all sealed decision records.

Query parameters:
- `severity_changed=true` — filter to only reclassified findings
- `confidence_below=0.7` — filter to low-confidence decisions
- `approach=adversarial_debate` — filter by approach used

#### `GET /api/v1/audit/adjudication/{scan_id}/finding/{finding_id}/history`

Decision history for a single finding. Returns the full chain of
adjudication decisions, ordered chronologically, including re-adjudications
with justifications and deltas.

#### `GET /api/v1/audit/adjudication/{scan_id}/summary`

Review-oriented summary for a scan:

```json
{
  "scan_id": "scan-xyz-789",
  "adjudication_runs": 2,
  "total_findings_adjudicated": 42,
  "severity_upheld": 28,
  "severity_adjusted": 14,
  "re_adjudicated_findings": 3,
  "adjustments": [
    {"from": "critical", "to": "high", "count": 2},
    {"from": "critical", "to": "medium", "count": 1},
    {"from": "high", "to": "medium", "count": 8},
    {"from": "medium", "to": "low", "count": 3}
  ],
  "low_confidence_decisions": 4,
  "approach_distribution": {
    "adversarial_debate": 12,
    "evidence_rubric": 18,
    "structured_challenge": 12
  },
  "anomaly_flags": [
    "Finding F-012 re-adjudicated 3 times (downgraded each time)",
    "2 critical findings adjudicated with structured_challenge (non-default)"
  ],
  "audit_forwarding_status": "all_forwarded",
  "chain_integrity": "valid"
}
```

The `anomaly_flags` field surfaces patterns a reviewer should examine.
These are heuristic, not definitive — they highlight areas for human
judgment:

- Repeated downgrade of the same finding across re-adjudications
- Use of a less rigorous approach on high-severity findings (when
  operator overrides auto-tiering)
- Low-confidence reclassifications
- Forwarding failures

#### `GET /api/v1/audit/adjudication/export`

Bulk export endpoint. Supports multiple formats:

- `format=json` — machine-readable, suitable for SIEM ingestion or
  programmatic analysis
- `format=csv` — tabular summary (one row per decision, flattened)
- `format=report` — structured human-readable report (Markdown or HTML),
  suitable for inclusion in pentest deliverables or compliance submissions

Query parameters:
- `scan_id` — required
- `format` — required (json | csv | report)
- `include_prompts=true` — include full LLM prompt/response text
  (default: false, since these can be large)

### Database Schema

New table: `adjudication_audit_log`

```sql
CREATE TABLE adjudication_audit_log (
    record_id       TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    finding_id      TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    -- sealed record content (JSON blob of complete decision record)
    sealed_record   JSON NOT NULL,
    -- denormalized fields for query efficiency
    original_severity    TEXT NOT NULL,
    adjudicated_severity TEXT NOT NULL,
    confidence           REAL NOT NULL,
    approach_used        TEXT NOT NULL,
    is_readjudication    BOOLEAN NOT NULL DEFAULT FALSE,
    justification        TEXT,
    -- integrity chain
    record_hash          TEXT NOT NULL,
    prior_record_hash    TEXT,
    chain_position       INTEGER NOT NULL,
    -- forwarding status
    forwarding_status    TEXT NOT NULL DEFAULT 'pending',
    forwarded_at         TIMESTAMP,
    -- timestamps
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_scan_id ON adjudication_audit_log(scan_id);
CREATE INDEX idx_audit_finding_id ON adjudication_audit_log(finding_id);
CREATE INDEX idx_audit_run_id ON adjudication_audit_log(run_id);
CREATE INDEX idx_audit_chain ON adjudication_audit_log(chain_position);
CREATE INDEX idx_audit_forwarding ON adjudication_audit_log(forwarding_status);
```

The `sealed_record` column stores the complete sealed decision record as
JSON. Denormalized columns exist solely for query performance — the
authoritative data is always the sealed record.

### New Events

```
AUDIT_RECORD_CREATED       — sealed decision record written
AUDIT_FORWARD_SUCCESS      — record forwarded to external collector
AUDIT_FORWARD_FAILED       — forwarding failed after all retries
AUDIT_CHECKPOINT           — chain checkpoint forwarded
READJUDICATION_REQUESTED   — re-adjudication triggered (includes justification)
```

### Implementation Notes

- The `operator_context_used` column in the existing `adjudication_results`
  table was designed to capture matched context but is currently unpopulated.
  This should be populated as part of this work — it feeds into the sealed
  decision record's `inputs.operator_context_matched` field.
- LLM prompt/response capture should use the existing `LLMClient`
  interface. The adjudicator agent already receives responses through this
  path — the change is storing the full request/response rather than
  discarding it after parsing.
- Forwarding configuration follows the existing `~/.chainsmith/` pattern.
  The audit config lives in `preferences.yaml` alongside other adjudicator
  settings.
- The retry queue for failed forwards should use a local SQLite table
  (same DB) to survive restarts. A background task drains the queue on
  startup.

### What This Does NOT Cover

- **Authentication/authorization** for the audit API endpoints. Chainsmith
  currently has no auth layer. When one is added, audit endpoints should
  require a distinct `audit:read` permission, separate from operational
  permissions. 2nd line reviewers should have audit access without scan
  execution access.
- **Signed timestamps from a trusted third party** (e.g., RFC 3161). This
  would provide cryptographic proof of *when* a record was created,
  independent of system clocks. Worth considering for environments with
  regulatory timestamp requirements, but not in initial scope.
- **Encryption at rest** for sealed records. The records contain LLM
  prompts/responses which may include sensitive finding details. Encryption
  should be addressed at the storage layer (DB-level encryption) rather
  than application-level per-record encryption.

## Retention Policy

Default retention is **keep-forever**. Audit gaps are more costly than storage.

- **Compression** — sealed decision records older than a configurable threshold
  (default: 90 days) are gzip-compressed in place. Full prompt/response text
  is the primary space consumer; compression typically achieves 80-90%
  reduction on text-heavy JSON. Compressed records are transparently
  decompressed on read via the audit API.
- **Deletion** — an optional `delete_after_days` setting in
  `~/.chainsmith/preferences.yaml` enables automatic purging of records older
  than the configured interval. **Disabled by default.** When enabled, deletion
  is logged as an `AUDIT_RECORDS_PURGED` event (forwarded to external
  collectors before local deletion occurs) so 2nd line has a record of what
  was removed and when.

```yaml
adjudicator:
  audit:
    retention:
      compress_after_days: 90       # gzip records older than this (default: 90)
      delete_after_days: null       # null = keep forever (default)
```

## Future Features

- **External threat intelligence** — EPSS scores, known-exploited-vulnerabilities
  catalog (KEV) to inform adjudication. Marketed as a future premium feature.
- **Learning loop** — adjudication results feed back into attack pattern weights
  over time.
- **RFC 3161 trusted timestamps** — cryptographic proof of record creation
  time for regulatory environments requiring independent timestamp authority.
- **Webhook payload signing and mTLS** — HMAC-SHA256 payload signatures for
  webhook forwarding and mutual TLS support for both webhook and syslog
  targets. Currently, webhook forwarding relies on bearer tokens and syslog
  uses server-side TLS only. A receiving SIEM cannot cryptographically verify
  the sender without payload signing or mTLS. This is a separate phase due to
  the certificate management and key distribution infrastructure required.

## Open Questions

- Should adjudication results feed back into attack pattern weights over time
  (learning loop)?
- Should the anomaly flags in the review summary be configurable (custom
  thresholds, additional patterns) or is a fixed set sufficient?

## Dependencies

- Phase 1-3 persistence (complete) — adjudication results need storage
- Verifier agent — Adjudicator operates on verified findings only
- Attack chain builder — for Phase 21b chain-level adjudication

## LLM Integration

All LLM calls are handled via the existing `get_llm_client()` path, resolved
from `--profile` in `chainsmith.sh`. A `model_adjudicator` field will be added
to `LiteLLMConfig` in `app/config.py` for per-agent model overrides, consistent
with `model_verifier` and `model_chainsmith`.

### Temperature and Determinism

All adjudication LLM calls **must** use `temperature=0` to maximize
reproducibility. This is critical for audit defensibility — a 2nd line
reviewer who re-runs the same prompt should get a substantially similar
result.

**Important caveat:** `temperature=0` does **not** guarantee identical
outputs across calls. LLM inference involves floating-point operations whose
ordering can vary between hardware, driver versions, batch sizes, and even
runs on the same GPU. Model providers may also update weights or
infrastructure without notice. The sealed decision record captures the
exact response that was produced, so the audit trail remains authoritative
regardless of whether a re-run yields a slightly different result. Reviewers
should treat the recorded output as the ground truth, not attempt exact
reproduction as a verification method.
