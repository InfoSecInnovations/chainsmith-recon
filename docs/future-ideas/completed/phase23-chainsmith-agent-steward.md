# Phase 23 — Chainsmith Agent: Check & Chain Steward

> **Note (Phase 39):** The "steward" identity was removed in Phase 39.
> All steward capabilities now live under the Chainsmith name with proper
> engine/repository wiring. This document is kept as historical record.

Repurpose the unused `ChainsmithAgent` as a steward that maintains, curates,
and validates an organization's check ecosystem. Chainsmith is not in the
scan pipeline — it manages the pipeline itself.

## Motivation

Organizations will customize their Chainsmith instance over time: adding
proprietary checks, disabling irrelevant ones, tweaking conditions and
thresholds, adding custom attack chain patterns. Today there is no mechanism
to validate that those customizations are coherent. Checks are hardcoded
imports in `check_resolver.py`, suite mapping is inferred from naming
patterns, and there is no separation between community-maintained and
organization-specific checks.

Things break quietly:
- A custom check requires an output that no other check produces
- An attack chain pattern references a check that was renamed or disabled
- Two custom checks produce the same output key, silently overwriting
- A community update adds a check that conflicts with a custom one
- Disabling a suite makes downstream suites silently dead

Chainsmith catches all of this.

## What Chainsmith Does

### Graph Validation

Analyze the full check dependency graph (conditions, produces, suite
dependencies) and report:

- **Dead checks** — conditions reference context keys that no check produces
- **Orphaned outputs** — a check produces keys that nothing consumes
- **Shadow conflicts** — two checks produce the same output key
- **Broken suite paths** — disabling checks makes entire suites unreachable
- **Circular dependencies** — condition loops that would stall the runner

### Attack Chain Pattern Validation

Cross-reference `chains.py` rule patterns against the active check registry:

- Pattern requires `check_name: "openapi_discovery"` but that check is
  disabled → pattern will never trigger
- Pattern references a finding title substring that no active check produces
- Custom pattern duplicates a community pattern with different severity

### Content-Aware Analysis

Beyond metadata (names, conditions, produces), Chainsmith reads check
implementations to reason about:

- **Semantic overlap** — custom `api_key_header_check` and built-in
  `header_analysis_check` both inspect `Authorization` headers. Intentional
  or redundant?
- **Coverage gaps** — "You have checks for `/v1/chat/completions` but nothing
  probes `/v1/embeddings` — consider adding embedding endpoint discovery"
- **Condition adequacy** — a check's conditions say it needs `services` but
  its code actually filters for `service_type == "ai"`. If no AI services are
  discovered, the check runs but finds nothing. Should the condition be
  tighter?

Content-aware analysis uses LLM reasoning. If unavailable or too expensive,
Chainsmith falls back to metadata-only validation, which is deterministic
and fast.

### Guided Customization

When an operator wants to add, modify, or disable checks, Chainsmith walks
them through it:

- "I want to add a check for our internal auth endpoint"
  → Chainsmith asks what the check needs as input, what it produces, which
    suite it belongs to, and generates the scaffold in `custom/`
- "Disable all MCP checks"
  → Chainsmith shows what breaks: "3 agent checks depend on MCP discovery
    outputs. Disable those too, or provide alternative context?"
- "We updated from upstream — what changed?"
  → Chainsmith diffs community checks against the last known state, flags
    conflicts with custom checks, suggests resolution

### Suggestions Before Changes

Chainsmith always suggests first, then asks permission to edit. It does not
modify files silently. Every proposed change is shown as a diff the operator
can approve or reject.


## Custom Checks Directory

### Structure

```
app/checks/
├── network/          # community (upstream)
├── web/              # community
├── ai/               # community
├── mcp/              # community
├── agent/            # community
├── rag/              # community
├── cag/              # community
├── custom/           # organization-specific
│   ├── __init__.py   # auto-generated registry
│   ├── my_auth_check.py
│   ├── internal_api_probe.py
│   └── ...
└── ...
```

### Why a Separate Directory

- **Clean upstream merges.** Community updates never touch `custom/`. No
  merge conflicts on proprietary code.
- **Clear ownership.** Everything in `custom/` is the org's responsibility.
  Chainsmith validates it but upstream doesn't ship it.
- **Explicit registration.** `custom/__init__.py` acts as a registry that
  `check_resolver.py` reads. Chainsmith maintains this file.
- **Gitignore-friendly.** Orgs can `.gitignore` `custom/` if they don't want
  proprietary checks in public forks, or keep it in a private submodule.

### Discovery Changes

`check_resolver.py` gains a second discovery path:

```python
def get_real_checks() -> list:
    checks = []
    
    # Community checks (existing hardcoded imports)
    checks.extend(_get_community_checks())
    
    # Custom checks (dynamic discovery from custom/)
    checks.extend(_get_custom_checks())
    
    return checks
```

Custom check discovery scans `app/checks/custom/` for classes that extend
`BaseCheck`, instantiates them, and validates that their metadata
(conditions, produces, suite) is well-formed. Chainsmith generates and
maintains `custom/__init__.py` as the authoritative registry.


## Chainsmith Agent Behavior Modes

```yaml
chainsmith_agent:
  mode: ask_before_run    # ask_before_run (default) | always_run | silent
```

- **ask_before_run** (default) — Chainsmith asks before running validation.
  "I'd like to check your dependency graph — OK?" Shows results, suggests
  fixes, asks permission before editing.
- **always_run** — Chainsmith runs validation automatically at configured
  trigger points. Still asks before making edits.
- **silent** — Never asks, never runs unless explicitly launched by the
  operator. For teams that want full manual control.

### Trigger Points

- **Pre-scan** — quick validation before launch: "These 3 checks won't run
  given your current config"
- **On upstream update** — community checks changed, diff against custom
- **On demand** — operator explicitly asks Chainsmith to audit

All triggers are user-invoked. No file watchers or automatic triggers.


## Interaction Model

Chainsmith is conversational. Examples:

**Operator:** "Add a check that looks for leaked JWT secrets in response bodies"

**Chainsmith:** "I'll create a new check in `custom/`. A few questions:
- Should this run against all HTTP services, or just API-typed ones?
- What conditions does it need? (I'd suggest: `services` truthy, same as
  other web checks)
- Should it produce an output key for downstream checks, or just findings?

Here's the scaffold I'd generate: [shows code]

Want me to create this file and register it?"

---

**Operator:** "Is my check graph healthy?"

**Chainsmith:** "I found 2 issues:
1. `custom/internal_api_probe.py` requires `internal_endpoints` but nothing
   produces that key. Did you mean `api_endpoints` (produced by
   `openapi_discovery`)?
2. Attack chain pattern `custom_data_exfil` references check
   `s3_bucket_enum` which doesn't exist in your instance.

Want me to fix issue 1 by updating the condition? Issue 2 needs a new
check or pattern edit — which do you prefer?"

---

**Operator:** "I just pulled the latest community checks. What changed?"

**Chainsmith:** "3 changes since your last sync:
1. `header_analysis_check` now also inspects `X-Request-ID` headers. No
   conflict with your custom checks.
2. New check: `websocket_probe_check` in the web suite. It produces
   `websocket_endpoints`. None of your custom checks consume this, but your
   custom `realtime_api_check` might benefit — want me to add it as a
   condition?
3. `llm_endpoint_discovery` renamed its output from `chat_endpoints` to
   `llm_endpoints`. YOUR CUSTOM CHECK `custom_prompt_test.py` references
   `chat_endpoints` — this will break. Want me to update it?"


## Content-Aware Analysis Detail

When operating in content-aware mode, Chainsmith reads the actual check
implementation (not just metadata) and reasons about:

### What it reads
- The HTTP paths/endpoints a check probes
- The request payloads and headers it sends
- The response patterns it matches against
- The finding types and severities it can produce
- The actual filtering logic (not just declared `service_types`)

### What it reasons about
- Semantic overlap between checks (two checks probing the same paths)
- Coverage completeness (known attack surfaces with no corresponding check)
- Condition tightness (declared conditions vs. actual runtime filtering)
- Finding quality (does the check capture enough evidence for Verifier?)

### Fallback
If LLM is unavailable, Chainsmith falls back to metadata-only validation:
names, conditions, produces, suite membership, pattern references. This is
deterministic, fast, and still catches the most common issues (dead checks,
broken patterns, shadow conflicts).


## Relationship to Other Components

Per the [component taxonomy](component-taxonomy.md), Chainsmith is an
**Agent** (LLM-powered for content-aware analysis, with deterministic
fallback for metadata-only validation).

| Component | Type | Relationship |
|---|---|---|
| **CheckRunner / ChainOrchestrator** | Engine | Chainsmith validates what these will execute, but doesn't replace them. They run checks; Chainsmith ensures the check set is coherent. |
| **chains.py** | Engine | Owns all attack chain logic (rule-based + LLM). Chainsmith validates that chain patterns reference checks that actually exist and are active. |
| **ScanAdvisor** | Advisor | ScanAdvisor says "you missed coverage on this scan." Chainsmith says "your check set has a structural gap — no check covers X." Adjacent but different: runtime vs. design-time. |
| **Verifier** | Agent | Verifier validates findings. Chainsmith validates the checks that produce findings. Different layers. |
| **Coach** | Agent | Coach explains what's happening. Chainsmith explains why the check graph is shaped the way it is. Coach is runtime; Chainsmith is configuration-time. |

## New Events

```
CHAINSMITH_VALIDATION_START
CHAINSMITH_VALIDATION_COMPLETE
CHAINSMITH_ISSUE_FOUND          # dead check, broken pattern, etc.
CHAINSMITH_FIX_SUGGESTED
CHAINSMITH_FIX_APPROVED
CHAINSMITH_FIX_APPLIED
CHAINSMITH_CUSTOM_CHECK_CREATED
CHAINSMITH_UPSTREAM_DIFF
```

## New Model Entries

The existing `AgentType.CHAINSMITH` enum value stays — it just gets a real
agent behind it again.

## Resolved Design Decisions

- **Circular dependency detection:** Chainsmith's responsibility, not
  CheckRunner's. CheckRunner trusts the check set it receives; Chainsmith
  validates the DAG before anything runs.
- **Root vs. produced keys:** Hardcode the seed key list from `scanner.py`'s
  `initial_context` (`base_domain`, `scope_domains`, `excluded_domains`,
  `services`, `port_profile`). Any consumed key not produced by a check and
  not in the seed list is flagged as a dead dependency.
- **LLM configuration:** Inherited from `--profile` at invocation. No
  per-component LLM config needed.
- **Semantic overlap threshold:** 0.7 confidence float. Generous but not
  overly sensitive.
- **Custom check registration:** Operator can register manually; Chainsmith
  validates after the fact. Not a gatekeeper.
- **Discovery timing:** At scan launch, before WebUI renders in index.html.
- **Trigger model:** User-invoked only. No file watchers, no automatic
  "on modification" triggers.
- **Version tracking:** Git (tags/hashes on the community check directory).
- **Advise vs. block:** Chainsmith advises and helps fix. Does not block
  scans. If an operator wants to run checks without addressing all issues,
  that's on them. Check developers will rely heavily on this behavior.
- **Check scaffolding depth:** Chainsmith generates a working implementation
  when LLM is available, falls back to stub with TODOs otherwise. All
  generated code requires human review before going live.
- **Multi-instance coordination:** Not in v1.
- **Basic instantiation checks:** Belongs in Chainsmith (can the check be
  instantiated? are conditions well-formed? does `run()` signature match?).
  Not required to pass before running a scan — advisory only. Deeper smoke
  tests remain in Phase 18.
- **Steward persistence:** JSON manifest in `custom/`, separate from all
  other data flows (no DB tables, no event store).

## Dependencies

- Phases 1-3 persistence (complete) — Chainsmith stores validation state in
  `custom/steward_manifest.json`, separate from DB persistence
- `check_resolver.py` — needs the dual-path discovery (community + custom)
- `app/checks/base.py` — custom checks extend `BaseCheck`, no changes needed
- Phase 18 test hardening (optional) — deeper smoke tests for custom checks
