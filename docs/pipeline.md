# Pipeline & Component Reference

Chainsmith's internal pipeline consists of **agents**, **gates**, and
**advisors** that process observations from discovery through remediation.
This document describes each component, how they connect, and how to
configure them.

> This is distinct from [`docs/checks/`](checks/overview.md), which
> documents the check suites (security tests run against external targets).

---

## Component Taxonomy

Every pipeline component falls into one of three types:

| Type | Defining trait | Cost | Deterministic | Works offline |
|------|---------------|------|---------------|---------------|
| **Agent** | LLM-powered autonomous reasoning | LLM tokens | No | No |
| **Gate** | Deterministic policy enforcement | Zero | Yes | Yes |
| **Advisor** | Deterministic post-hoc analysis | Zero | Yes | Yes |

**Agents think. Gates block. Advisors suggest.**

This matters for:

- **Cost** — agents incur LLM costs per invocation; gates and advisors do not.
- **Reproducibility** — gates and advisors produce identical output for
  identical input; agent output varies across runs.
- **Offline/airgapped operation** — gates and advisors work without LLM
  access; agents require it.
- **Model selection** — each agent has its own model override
  (e.g. `LITELLM_MODEL_VERIFIER`); gates and advisors ignore model config.
- **Trust model** — gate decisions are authoritative; agent outputs carry
  uncertainty expressed as confidence scores.

---

## Pipeline Flow

```
Scoping (Chainsmith — conversational)              AGENT
    |
    v
Guardian (scope enforcement)                       GATE
    |
    v
Scanning (check suites execute)
    |
    v
Verification (Verifier)                            AGENT
    |
    v
Research Enrichment (Researcher)                   AGENT
    |
    v
Chain Analysis (Chainsmith — pattern + LLM)        AGENT
    |
    v
Adjudication (Adjudicator)                         AGENT
    |
    v
Triage (Triage)                                    AGENT
    |
    v
ScanAdvisor (post-scan recommendations)            ADVISOR
    |
    v
CheckProof (reproduction guidance)                 ADVISOR
    |
    v
Reporting
```

Two components sit outside the linear pipeline:

- **Coach** — always-available conversational explainer, accessible at any
  point during a session.
- **Steward** (Chainsmith) — check ecosystem validation and custom check
  management, invoked on demand.

---

## Gates

### Guardian

`app/guardian.py`

- **Role:** Scope enforcement. Validates URLs and techniques against the
  operator-defined scope before any check executes. Also enforces
  engagement window restrictions.
- **Consumes:** URLs, technique names, `ScopeDefinition`.
- **Produces:** Approve/reject decisions with violation reasons.
- **When it runs:** Continuously during scanning; every request is checked.

**Key methods:**

| Method | Purpose |
|--------|---------|
| `check_url(url)` | Validate domain against scope patterns (supports wildcards) |
| `check_technique(technique)` | Check if technique is forbidden |
| `validate_request(url, technique)` | Combined URL + technique validation |
| `approve_url(url)` / `deny_url(url)` | Manual operator override |

**Events emitted:**

| Event | Importance |
|-------|------------|
| `SCOPE_VIOLATION` | HIGH |
| `SCOPE_APPROVED` | LOW |
| `SCOPE_DENIED` | LOW |

**Configuration:**

```yaml
scope:
  in_scope_domains:
    - "*.example.com"
  out_of_scope_domains:
    - vpn.example.local
  in_scope_ports: [80, 443, 8080, 8443]
  allowed_techniques: []       # empty = all allowed
  forbidden_techniques: []
  time_window: null             # engagement window restriction
```

Port profiles (`--port-profile`): `web`, `ai`, `full`, `lab`.

---

## Agents

### Verifier

`app/agents/verifier.py`

- **Role:** Fact-checks observations, catches hallucinations, assigns
  confidence scores and evidence quality ratings.
- **Consumes:** Pending observations.
- **Produces:** Observations updated with status (VERIFIED / REJECTED /
  HALLUCINATION), confidence (0.0-1.0), evidence quality, and
  verification notes.
- **When it runs:** After scanning, before chain analysis.
- **LLM approach:** Multi-turn tool-use loop (max 20 iterations).

**Tools available to the LLM:**

| Tool | Purpose |
|------|---------|
| `verify_cve(cve_id)` | Check NVD database |
| `verify_version(software, claimed_version, evidence)` | Validate version claims |
| `verify_endpoint(base_url, endpoint)` | Check endpoint accessibility |
| `submit_verdict(observation_id, status, confidence, evidence_quality, reasoning)` | Record final verdict |

**Evidence quality levels:** `DIRECT_OBSERVATION`, `INFERRED`,
`CLAIMED_NO_PROOF`.

**Events emitted:**

| Event | Importance |
|-------|------------|
| `AGENT_START` | MEDIUM |
| `TOOL_CALL` / `TOOL_RESULT` | LOW |
| `HALLUCINATION_CAUGHT` | HIGH |
| `OBSERVATION_VERIFIED` | MEDIUM |
| `OBSERVATION_REJECTED` | LOW |
| `AGENT_COMPLETE` | MEDIUM |
| `ERROR` | HIGH |

**Configuration:**

| Setting | Default |
|---------|---------|
| `LITELLM_MODEL_VERIFIER` | `nova-mini` |

---

### Adjudicator

`app/agents/adjudicator.py`

- **Role:** Challenges severity ratings using a CVSS-like evidence rubric
  with operator asset context.
- **Consumes:** Verified observations + optional `OperatorContext`
  (asset exposure and criticality metadata).
- **Produces:** `AdjudicatedRisk` per observation — original vs.
  adjudicated severity, confidence, rationale, and factor scores.
- **When it runs:** After verification, before triage.
- **LLM approach:** Single structured call per observation.

**Rubric factors** (each scored 0.0-1.0):

| Factor | What it measures |
|--------|-----------------|
| `exploitability` | How easy to exploit |
| `impact` | Damage potential |
| `reproducibility` | How reliably it reproduces |
| `asset_criticality` | Business importance of the affected asset |
| `exposure` | Internet-facing vs. internal |

**Severity mapping** (average of five factors):
critical >= 0.8, high >= 0.6, medium >= 0.4, low >= 0.2, info < 0.2.

**Events emitted:**

| Event | Importance |
|-------|------------|
| `ADJUDICATION_START` | MEDIUM |
| `SEVERITY_UPHELD` | LOW |
| `SEVERITY_ADJUSTED` | HIGH |
| `ADJUDICATION_COMPLETE` | MEDIUM |
| `ERROR` | MEDIUM |

**Configuration:**

| Setting | Default |
|---------|---------|
| `LITELLM_MODEL_ADJUDICATOR` | `nova-pro` |
| `adjudicator.enabled` | `true` |
| `adjudicator.context_file` | `~/.chainsmith/adjudicator_context.yaml` |

> **Note:** The `AdjudicationApproach` enum retains `STRUCTURED_CHALLENGE`,
> `ADVERSARIAL_DEBATE`, and `AUTO` values for database backward
> compatibility. Only `EVIDENCE_RUBRIC` is active.

---

### Triage

`app/agents/triage.py`

- **Role:** Produces a prioritized remediation action plan with
  effort/impact matrix, workstream grouping, and team context awareness.
- **Consumes:** Verified observations, adjudicated risks, attack chains,
  optional `OperatorContext`, optional `TeamContext`, optional remediation
  KB entries.
- **Produces:** `TriagePlan` containing prioritized `TriageAction` items,
  executive summary, workstream groupings, and quick-win / strategic-fix
  counts.
- **When it runs:** After adjudication — final analytical pipeline stage.
- **LLM approach:** Single structured call.

**Prioritization factors** (in order):

1. Chain membership — entry-point fixes are leverage.
2. Adjudicated severity.
3. Exploitability.
4. Consolidation — actions that resolve multiple observations.
5. Effort/impact ratio — quick wins first.
6. Asset criticality.

**Action feasibility levels:**

| Level | Meaning |
|-------|---------|
| `DIRECT` | Team can fix without external help |
| `ESCALATE` | Requires coordination with another team |
| `BLOCKED` | Outside the team's remediation surface |

**Team context signals** (from litmus questions):

| Signal | Values | Effect |
|--------|--------|--------|
| `deployment_velocity` | yes / with_approval / no | Affects deploy-required fix feasibility |
| `incident_response` | yes / partially / no | Affects credential action feasibility |
| `remediation_surface` | both / app_only / infra_only / neither | Marks ESCALATE or BLOCKED |
| `team_size` | solo / 2_to_3 / 4_plus | Enables workstream grouping |
| `off_limits` | free text | Marks BLOCKED |

**Events emitted:**

| Event | Importance |
|-------|------------|
| `TRIAGE_START` | MEDIUM |
| `TRIAGE_ACTION` | Varies (by impact) |
| `TRIAGE_COMPLETE` | MEDIUM |

**Configuration:**

| Setting | Default |
|---------|---------|
| `LITELLM_MODEL_TRIAGE` | `nova-pro` |
| `triage.enabled` | `true` |
| `triage.context_file` | `~/.chainsmith/triage_context.yaml` |
| `triage.kb_path` | `app/data/remediation_guidance.json` |

---

### Chainsmith (Chain Builder + Steward)

`app/agents/chainsmith.py`

This agent has two roles that share a codebase:

#### Chain Builder

- **Role:** Builds attack chains from verified observations using pattern
  matching and optional LLM-powered discovery.
- **Consumes:** Verified observations, optional operator context.
- **Produces:** `AttackChain` objects — linked observations with combined
  severity, attack steps, prerequisites, and confidence scores.
- **When it runs:** After verification, during chain analysis phase.

**Key methods:**

| Method | Purpose |
|--------|---------|
| `build_chains(observations, operator_context)` | Entry point for chain building |
| `_match_patterns(observations)` | Pattern-based chain detection |
| `_llm_discover_chains(observations)` | LLM reasoning for novel chains |

#### Steward

- **Role:** Validates and curates the check ecosystem — graph validation,
  custom check scaffolding, upstream diff detection, and content analysis.
- **Consumes:** Check registry, custom check manifest, community check
  hashes.
- **Produces:** `ValidationResult` with issues, health status, and
  summary.
- **When it runs:** On demand (via `/api/v1/steward/` or operator request).

**Validation issue categories:**

| Category | Meaning |
|----------|---------|
| `dead_check` | Check produces nothing, nothing consumes its output |
| `orphaned_output` | Output produced but never consumed |
| `shadow_conflict` | Two checks produce the same key (race condition) |
| `cycle_detected` | Circular dependency in conditions/produces |
| `broken_reference` | Pattern references a non-existent check |
| `unreachable_pattern` | Pattern can never trigger |

**Key methods:**

| Method | Purpose |
|--------|---------|
| `validate(checks)` | Full graph + pattern validation |
| `scaffold_check(...)` | Generate custom check boilerplate |
| `write_and_register_check(...)` | Write to disk + update manifest |
| `suggest_disable_impact(check_names)` | Impact analysis for disabling checks |
| `diff_upstream()` | Detect community check changes since last sync |
| `content_analysis(checks)` | LLM-powered semantic overlap + gap analysis |

**Events emitted:**

| Event | Importance |
|-------|------------|
| `CHAIN_IDENTIFIED` | MEDIUM |
| `STEWARD_VALIDATION_START` | LOW |
| `STEWARD_ISSUE_FOUND` | MEDIUM |
| `STEWARD_VALIDATION_COMPLETE` | LOW |
| `STEWARD_UPSTREAM_DIFF` | Varies |
| `STEWARD_CUSTOM_CHECK_CREATED` | MEDIUM |

**Configuration:**

| Setting | Default |
|---------|---------|
| `LITELLM_MODEL_CHAINSMITH` | `nova-pro` |
| `LITELLM_MODEL_CHAINSMITH_FALLBACK` | `nova-mini` |
| Custom checks directory | `app/checks/custom/` |
| Manifest | `app/checks/custom/steward_manifest.json` |

---

### Researcher

`app/agents/researcher.py`

- **Role:** Enriches verified observations with external context — CVE
  details, public exploits, vendor advisories, version vulnerabilities.
- **Consumes:** Observations to enrich, optional offline mode flag.
- **Produces:** Observations with populated `ResearchEnrichment`
  containing CVE details, exploit availability, vendor advisories,
  version vulnerabilities, and data source attribution.
- **When it runs:** After verification, before or alongside chain
  analysis.
- **LLM approach:** Multi-turn tool-use loop.

**Tools available to the LLM:**

| Tool | Purpose |
|------|---------|
| `lookup_cve(cve_id)` | NVD details |
| `lookup_exploit_db(cve_id)` | Public exploit search |
| `fetch_vendor_advisory(url)` | Vendor security bulletins |
| `enrich_version_info(product, version)` | Version-specific vulnerabilities |
| `submit_enrichment(observation_id, ...)` | Record enrichment |

**Events emitted:**

| Event | Importance |
|-------|------------|
| `RESEARCH_REQUESTED` | MEDIUM |
| `TOOL_CALL` / `TOOL_RESULT` | LOW |
| `RESEARCH_COMPLETE` | MEDIUM |
| `ERROR` | MEDIUM |

**Configuration:**

| Setting | Default |
|---------|---------|
| `researcher.enabled` | `true` |
| `researcher.offline_mode` | `false` |
| `researcher.data_sources` | `["nvd", "exploitdb", "vendor_advisories"]` |

---

### Coach

`app/agents/coach.py`

- **Role:** Always-available conversational assistant that explains
  anything happening in a Chainsmith session. Grounds answers in
  session context.
- **Consumes:** Operator question + optional session state (observations,
  chains, recent events, scope summary).
- **Produces:** Plain-language explanatory text.
- **When it runs:** Any time the operator asks an explanatory question.
- **LLM approach:** Single call, no tools. Temperature 0.3, max
  2000 tokens.

Coach does not take actions. It directs operators to the right component:

> "For scan suggestions, ask ScanAdvisor. To reproduce, ask CheckProof.
> To challenge severity, trigger Adjudicator. For remediation priorities,
> ask Triage. To validate checks, ask Steward."

**Memory:** Session-scoped deque (default max 10 exchanges). Clears when
the operator clears chat. No persistence across sessions.

**Events emitted:**

| Event | Importance |
|-------|------------|
| `COACH_QUERY` | LOW |
| `COACH_RESPONSE` | LOW |

**Configuration:**

| Setting | Default |
|---------|---------|
| `coach.enabled` | `true` |
| `coach.context_window` | `summary` |
| `coach.max_recent_events` | `50` |
| `coach.memory_cap` | `10` |

---

## Advisors

### ScanAdvisor

`app/scan_advisor.py`

- **Role:** Post-scan analysis — identifies gaps, partial results,
  follow-up opportunities, and coverage shortfalls.
- **Consumes:** Completed scan state (completed/failed/skipped checks,
  registry, context, observations).
- **Produces:** `ScanAdvisorRecommendation` list with check name, reason,
  context injection hints, confidence, and category.
- **When it runs:** After scan completion (disabled by default).

**Analysis layers:**

1. **Gap analysis** — checks that couldn't run due to missing context.
2. **Partial results** — checks that failed or were skipped.
3. **Follow-up rules** — deeper checks triggered by initial observations
   (e.g. port_scan findings trigger service_probe suggestion).
4. **Coverage cross-reference** — flags suites with low execution
   relative to available checks.

**Recommendation categories:** `gap_analysis`, `config_suggestion`,
`context_seed`, `speculative`.

**Configuration:**

| Setting | Default |
|---------|---------|
| `scan_advisor.enabled` | `false` |
| `scan_advisor.mode` | `post_scan` |
| `scan_advisor.auto_seed_urls` | `false` |
| `scan_advisor.require_approval` | `true` |

---

### CheckProof Advisor

`app/advisors/check_proof.py`

- **Role:** Generates templated reproduction steps and copy-pasteable
  commands for verified findings.
- **Consumes:** Verified observations, optional `ResearchEnrichment`
  from Researcher, YAML proof templates.
- **Produces:** `ProofGuidance` per observation — proof steps (tool +
  command + expected output), evidence checklist, false-positive
  indicators, and common mistakes.
- **When it runs:** On operator request or automatically for verified
  observations (configurable trigger).

**Template placeholders:** `{target_url}`, `{host}`, `{endpoint_path}`,
`{port}`, `{finding_id}`, `{severity}`, `{cve_id}`, `{cvss_score}`,
`{evidence}`, and more.

**Template location:** `app/data/proof_templates/` (YAML files).

**Configuration:**

| Setting | Default |
|---------|---------|
| `check_proof.enabled` | `true` |
| `check_proof.trigger` | `operator_selected` |
| `check_proof.include_commands` | `true` |
| `check_proof.include_screenshots` | `true` |
| `check_proof.template_dir` | `app/data/proof_templates/` |

---

## Prompt Router

`app/engine/prompt_router.py`

The prompt router is invisible infrastructure that classifies operator
messages and dispatches them to the correct component. It is not an agent,
gate, or advisor — it is plumbing.

**Three-layer routing strategy:**

1. **Context routing** (zero cost) — if the UI is already in a specific
   context (e.g. viewing adjudication results), route there.
2. **Keyword routing** (zero cost) — regex pattern matching on the
   operator's message.
3. **LLM fallback** — small/fast model classification when keyword
   confidence is below 0.6.

**Keyword routing rules:**

| Pattern | Routes to |
|---------|-----------|
| scope, scoping | Chainsmith |
| chain, attack path | Chainsmith |
| steward, validate checks, check graph | Chainsmith (Steward) |
| severity, risk, adjudicate | Adjudicator |
| verify, verification | Verifier |
| prioritize, remediate | Triage |
| proof, reproduce | CheckProof Advisor |
| explain, teach, understand | Coach |
| research, enrich, lookup | Researcher |

**Output:** `RouteDecision` with target agent, method, confidence, and
optional clarification prompt.

---

## Event System

All agents emit `AgentEvent` objects that power the live operator feed.

**AgentEvent fields:**

| Field | Type | Purpose |
|-------|------|---------|
| `event_type` | `EventType` | What happened |
| `agent` | `AgentType` | Who emitted it |
| `importance` | `EventImportance` | UI display priority |
| `timestamp` | `datetime` | When it happened |
| `message` | `str` | Human-readable description |
| `details` | `dict` or `null` | Structured metadata |
| `observation_id` | `str` or `null` | Related observation |
| `chain_id` | `str` or `null` | Related chain |
| `tool_name` | `str` or `null` | Tool that was called |
| `violation_url` | `str` or `null` | URL that triggered a scope violation |
| `requires_approval` | `bool` | Whether operator must approve |

**Importance levels:**

| Level | Meaning | UI hint |
|-------|---------|---------|
| `HIGH` | Significant — hallucinations, scope violations, severity changes | Red |
| `MEDIUM` | Notable — agent lifecycle, verification results | Yellow |
| `LOW` | Routine — tool calls, enumeration progress | Gray |

**Event types by component:**

| Component | Events |
|-----------|--------|
| Guardian | `SCOPE_VIOLATION`, `SCOPE_APPROVED`, `SCOPE_DENIED` |
| Verifier | `AGENT_START`, `TOOL_CALL`, `TOOL_RESULT`, `OBSERVATION_VERIFIED`, `OBSERVATION_REJECTED`, `HALLUCINATION_CAUGHT`, `AGENT_COMPLETE`, `ERROR` |
| Adjudicator | `ADJUDICATION_START`, `SEVERITY_UPHELD`, `SEVERITY_ADJUSTED`, `ADJUDICATION_COMPLETE`, `ERROR` |
| Triage | `TRIAGE_START`, `TRIAGE_ACTION`, `TRIAGE_COMPLETE` |
| Chainsmith | `CHAIN_IDENTIFIED`, `STEWARD_VALIDATION_START`, `STEWARD_ISSUE_FOUND`, `STEWARD_VALIDATION_COMPLETE`, `STEWARD_UPSTREAM_DIFF`, `STEWARD_CUSTOM_CHECK_CREATED`, `STEWARD_FIX_SUGGESTED`, `STEWARD_FIX_APPLIED` |
| Researcher | `RESEARCH_REQUESTED`, `TOOL_CALL`, `TOOL_RESULT`, `RESEARCH_COMPLETE`, `ERROR` |
| Coach | `COACH_QUERY`, `COACH_RESPONSE` |
| CheckProof | `PROOF_GUIDANCE_REQUESTED`, `PROOF_GUIDANCE_GENERATED` |
| Any | `INFO`, `ERROR` |

---

## Configuration Reference

### Environment Variables

All LLM model overrides follow the pattern `LITELLM_MODEL_<AGENT>` or
`CHAINSMITH_LITELLM_MODEL_<AGENT>`:

| Variable | Default | Used by |
|----------|---------|---------|
| `LITELLM_BASE_URL` | `http://localhost:4000/v1` | All agents |
| `LITELLM_MODEL_VERIFIER` | `nova-mini` | Verifier |
| `LITELLM_MODEL_CHAINSMITH` | `nova-pro` | Chainsmith |
| `LITELLM_MODEL_CHAINSMITH_FALLBACK` | `nova-mini` | Chainsmith (fallback) |
| `LITELLM_MODEL_ADJUDICATOR` | `nova-pro` | Adjudicator |
| `LITELLM_MODEL_TRIAGE` | `nova-pro` | Triage |

### YAML Configuration

All settings live in `chainsmith.yaml` (or the path in
`CHAINSMITH_CONFIG`). Component-specific blocks:

```yaml
scope:
  in_scope_domains: ["*.example.com"]
  out_of_scope_domains: ["vpn.example.local"]
  in_scope_ports: [80, 443, 8080, 8443]
  allowed_techniques: []
  forbidden_techniques: []

litellm:
  base_url: http://localhost:4000/v1
  model_verifier: nova-mini
  model_chainsmith: nova-pro
  model_chainsmith_fallback: nova-mini
  model_adjudicator: nova-pro
  model_triage: nova-pro

adjudicator:
  enabled: true
  context_file: ~/.chainsmith/adjudicator_context.yaml

triage:
  enabled: true
  context_file: ~/.chainsmith/triage_context.yaml
  kb_path: app/data/remediation_guidance.json

scan_advisor:
  enabled: false
  mode: post_scan
  require_approval: true

researcher:
  enabled: true
  offline_mode: false
  data_sources: ["nvd", "exploitdb", "vendor_advisories"]

coach:
  enabled: true
  context_window: summary
  max_recent_events: 50
  memory_cap: 10

check_proof:
  enabled: true
  trigger: operator_selected
  template_dir: app/data/proof_templates/
```

### External Files

| File | Purpose | Used by |
|------|---------|---------|
| `~/.chainsmith/adjudicator_context.yaml` | Operator asset context | Adjudicator |
| `~/.chainsmith/triage_context.yaml` | Team context (litmus answers) | Triage |
| `app/data/remediation_guidance.json` | Remediation knowledge base | Triage |
| `app/data/proof_templates/*.yaml` | Proof command templates | CheckProof |
| `app/checks/custom/steward_manifest.json` | Custom check registry | Chainsmith (Steward) |

---

## Related Documentation

- [Check Reference](checks/overview.md) — documents the check suites
  (external-facing security tests), not the internal pipeline
- [Swarm Architecture](swarm-architecture.md) — distributed execution
  topology, not the per-node pipeline
- [Operating Modes](OPERATING_MODES.md) — scan modes; cross-references
  this doc for pipeline detail
- [Component Taxonomy](future-ideas/completed/component-taxonomy.md) —
  canonical classification of all component types
