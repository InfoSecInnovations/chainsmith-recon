# Phase 22 — Verification Enhancements, Researcher, CheckProofAdvisor & Coach

Five complementary changes that strengthen how findings are enriched,
validated, contextualized, and explained to operators — plus a unified
chat API that ties conversational access together.

## 1. Verifier Enhancements (existing agent, minor changes)

The current Verifier is a mechanical fact-checker: CVE lookup, version match,
endpoint probe, verdict stamp. Its role stays the same — these are targeted
improvements to the quality of its output.

### Evidence grading

Alongside the verdict, tag the quality of the evidence that led to it.

```
evidence_quality: direct_observation | inferred | claimed_no_proof
```

- `direct_observation` — Verifier's own tool confirmed the claim (endpoint
  returned 200, CVE exists in NVD).
- `inferred` — evidence is consistent but not conclusive (version string in
  header matches known-vulnerable range, but no direct probe).
- `claimed_no_proof` — ScanAdvisor reported a finding with no verifiable evidence
  attached.

`evidence_quality` is added to the `Observation` model alongside the existing
verification fields (`verified_by`, `verified_at`, `verification_notes`).
CheckProofAdvisor keys off this field to decide how much reproduction guidance
the operator needs.

### Richer verification_notes

Current `verification_notes` are terse and LLM-facing. Expand them so
downstream components (CheckProofAdvisor, Coach) and the operator get more
signal without changing the Verifier's role.

Before: `"CVE-2021-41773 confirmed in NVD"`
After:  `"CVE-2021-41773 exists in NVD. Published 2021-10-05, CVSS 7.5. Affects Apache 2.4.49-2.4.50. ScanAdvisor's claimed version (2.4.49) falls within the affected range."`

When Researcher has been run before Verifier, the Verifier consumes
Researcher's structured enrichment data to produce these richer notes.
When Researcher has not been run, Verifier falls back to its existing tool
output (terse notes, same as today).

### No new responsibilities

Verifier stays a gate. It does not contextualize, teach, or advise. It
validates and stamps.


## 2. Researcher (new Agent — LLM-powered)

An enrichment agent that gathers external context about findings before
(or independent of) verification. Researcher owns the "go learn everything
about this thing" responsibility.

**Component type: Agent.** Researcher uses LLM reasoning to decide what
additional context is useful and how to interpret results from external
sources. See [component-taxonomy.md](completed/component-taxonomy.md) for
the taxonomy.

### Core responsibilities

- **CVE enrichment** — publish date, CVSS score, affected version ranges,
  advisory links, exploit availability.
- **Version-to-vulnerability mapping** — given a product and version, find
  all known vulnerabilities and their severity.
- **Exploit availability** — whether public exploits exist (ExploitDB,
  GitHub advisories, etc.).
- **Vendor advisory lookups** — pull relevant vendor security bulletins.

### Tools

- `lookup_cve(cve_id)` — fetch CVE details from NVD (description, CVSS,
  affected versions, references).
- `lookup_exploit_db(cve_id)` — check ExploitDB for public exploits.
- `fetch_vendor_advisory(url)` — retrieve vendor security bulletin content.
- `enrich_version_info(product, version)` — find known vulnerabilities for
  a specific product/version combination.

All tools support an **offline mode** where they return cached/bundled data
or graceful "not available — running in offline mode" responses. See
`future-improvements.md` for the offline mode enhancement roadmap.

### Output

Researcher produces a structured enrichment record attached to each
observation it processes:

```
ResearchEnrichment:
  observation_id: str
  cve_details: list[CVEDetail]        # CVSS, publish date, affected range
  exploit_availability: list[Exploit]  # source, url, verified
  vendor_advisories: list[Advisory]    # url, summary, date
  version_vulnerabilities: list[str]   # known vulns for detected version
  enriched_at: datetime
  data_sources: list[str]             # which sources were consulted
  offline_mode: bool                  # true if running without network
```

### Pipeline position

Independent. The documentation recommends running Researcher before Verifier
so that Verifier can consume enrichment data for richer verification notes,
but this is not required. Researcher can run at any time on any observation.

```
Recommended flow:  ScanAdvisor -> Researcher -> Verifier -> CheckProofAdvisor
Also valid:        ScanAdvisor -> Verifier -> Researcher -> CheckProofAdvisor
Also valid:        ScanAdvisor -> Verifier (Researcher never runs)
```

### No blocking dependencies

Researcher never gates the pipeline. If it hasn't run, downstream components
work with whatever data they already have (same as today).


## 3. CheckProofAdvisor (new Advisor — deterministic)

Sits after Verifier in the pipeline. Takes verified findings and helps the
operator independently confirm them and build report-quality evidence.

**Component type: Advisor.** CheckProofAdvisor generates templated
reproduction steps from check metadata, observation evidence, and
verification notes. It does not use LLM calls — its output is deterministic
and rule-based. See [component-taxonomy.md](completed/component-taxonomy.md)
for the taxonomy.

### Core responsibilities

- **Reproduction steps** — exact commands (curl, nmap, Burp) to independently
  confirm the finding.
- **Evidence checklist** — what a complete write-up needs (raw response capture,
  screenshot with timestamp, version-to-CVE mapping).
- **Severity justification** — why this severity holds up given the context,
  or flags where it might not.
- **False positive indicators** — what would make this finding not real, so the
  operator knows what to look for.

### Implementation approach

CheckProofAdvisor is deterministic — it templates reproduction commands from
observation metadata rather than generating them via LLM:

- Maps check types to proof command templates stored in **YAML data files**
  (`app/data/proof_templates/`). Templates are static strings populated via
  string interpolation from observation fields.
- Populates templates from observation evidence, target URL, and raw data.
- Looks up CVE details from Researcher enrichment data or cached verification
  data.
- Pulls raw evidence from session state.

It never discovers new things. It works with what Verifier already stamped.

### Proof templates

Templates live in YAML, organized by check type:

```yaml
# app/data/proof_templates/header_analysis.yaml
check_type: header_analysis
proof_steps:
  - tool: curl
    command: "curl -s -D- {target_url} | grep -i \"{header_name}\""
    expected_output: "No {header_name} header present in response headers"
    screenshot_worthy: false
  - tool: browser
    command: "Open DevTools > Network tab, navigate to {target_url}, inspect response headers"
    expected_output: "{header_name} header missing from response"
    screenshot_worthy: true
```

### Triggering

Operator-selected, not automatic. The operator picks which findings they want
proof guidance for via API call or CLI. This keeps it practical — not every
Info-severity header disclosure needs a proof walkthrough.

### Output model

```
ProofStep:
  tool: str                            # curl, nmap, burp, browser, etc.
  command: str                         # exact command to run
  expected_output: str                 # what confirms the finding
  screenshot_worthy: bool

ProofGuidance:
  finding_id: str
  finding_title: str
  verification_status: str             # from Verifier
  evidence_quality: str                # from Verifier

  proof_steps: list[ProofStep]         # one or more reproduction steps

  evidence_checklist:
    - description: str
      captured: bool                   # false = operator still needs this

  severity_rationale: str              # why this severity, in context

  false_positive_indicators: list[str] # what would disprove this

  common_mistakes: list[str]           # pitfalls when verifying this type
```

### Relationship to Adjudicator

CheckProofAdvisor and Adjudicator are **fully independent concerns**.

- CheckProofAdvisor answers: "Is this finding real? Here's how to prove it."
  (deterministic reproduction guidance)
- Adjudicator answers: "Is this severity correct?" (LLM-powered severity
  litigation, operator-triggered)

They do not consume each other's output. They can run in any order or
independently.


## 4. Coach (new Agent — LLM-powered)

An always-available conversational agent that explains anything happening
inside Chainsmith. No tools. Pure LLM conversation grounded in session
context.

**Component type: Agent.** Coach uses LLM reasoning to generate contextual
explanations. Despite having no tools, it requires LLM calls and its outputs
carry the uncertainty inherent to all agents. See
[component-taxonomy.md](completed/component-taxonomy.md) for the taxonomy.

### What it answers

- "What is a CORS misconfiguration and why does it matter?"
- "Why did ScanAdvisor run HeaderAnalysis before ChatEndpointDiscovery?"
- "What does it mean that Verifier rejected F-004?"
- "Explain this attack chain like I'm presenting to a non-technical stakeholder"
- "What's the difference between verified and hallucination?"
- "Why did Guardian block that request?"

### Design constraints

- **No tools.** Coach never probes, fetches, or modifies anything. It receives
  session state as context and reasons over it conversationally.
- **No pipeline position.** Coach is a sidebar — available at any time, not
  gated by pipeline stage.
- **Explains, does not tutor.** Coach explains results and concepts. It does
  not proactively suggest what the operator should investigate next — that is
  ScanAdvisor's tutor mode (Phase 20). Coach **does** know about ScanAdvisor
  and will direct operators to use it when appropriate (e.g., "If you want
  suggestions on what to scan next, try asking ScanAdvisor").
- **Explains results and concepts**, not internal code architecture. It talks
  about what the operator is seeing and the security concepts behind it.

### Context injection

Coach receives a curated session summary rather than the full session state,
to keep its context window manageable and responses fast:

- Current scope definition
- Finding summaries (id, title, severity, status, verification_notes)
- Chain summaries (id, title, combined_severity, attack_steps)
- Recent events (last N from the live feed)

This summary is assembled on-demand when the operator asks Coach a question,
not streamed continuously.

### Session-scoped memory

Coach maintains a capped history of prior Q&A exchanges within the current
session, enabling multi-turn conversation ("What about F-005?" after asking
about F-003).

- Memory is **session-scoped** — it does not persist across sessions.
- **Clearing the chat clears Coach memory.** No hidden state survives a clear.
- **Capped** at a configurable number of recent exchanges (default: 10) to
  prevent anchor and recency bias from long conversation histories. Older
  exchanges naturally fall off.

### System prompt character

- Plain language, no jargon-for-jargon's-sake
- Adjusts depth to the question — one-liner for "what does CORS mean?",
  detailed walkthrough for "explain this chain's impact"
- References specific findings by ID when relevant ("F-003 shows the Server
  header returning Apache/2.4.49 — that version number is the key piece
  because...")
- Never speculates about findings it can't see in the session context
- Knows about other Chainsmith components and directs operators to the right
  one ("For proof commands to reproduce this finding, ask CheckProofAdvisor")


## 5. Unified Chat API

A single chat endpoint that routes all operator-to-agent conversation.

### Endpoint

```
POST /api/v1/chat
```

**Request:**
```json
{
  "message": "explain F-003",
  "agent": "coach",        // optional — if omitted, PromptRouter classifies
  "scan_id": "abc123"      // optional — scopes context to a specific scan
}
```

**Response:** Streamed or synchronous agent response, depending on agent type.

### Routing

If `agent` is specified, the message routes directly to that agent. If
omitted, the existing `PromptRouter` classifies the intent:

1. Context routing (UI state, zero cost)
2. Keyword routing (regex patterns, zero cost)
3. LLM fallback (small/fast model classification)

All existing agent chat migrates to this endpoint over time. For Phase 22,
Coach and CheckProofAdvisor are routed through it. Other agents can be
migrated in subsequent phases.

### CLI access

The CLI wraps API calls. Pattern:

```bash
./chainsmith chat "explain F-003"
./chainsmith chat --agent coach "explain this attack chain"
./chainsmith chat --agent check_proof_advisor "how do I prove F-007?"
```


## New model entries

Per the [component taxonomy](completed/component-taxonomy.md), these components
should be registered under their correct type. If Phase 26 lands
`ComponentType`:

```python
# Agents (LLM-powered)
COACH = "coach"
RESEARCHER = "researcher"

# Advisors (deterministic)
CHECK_PROOF_ADVISOR = "check_proof_advisor"
```

If `AgentType` is still the only enum, all are added there but documented
with their true classification.

Note: `PROOF_ADVISOR` already exists in `AgentType`. Rename it to
`CHECK_PROOF_ADVISOR` to reflect the scoped name.

## New events

```
RESEARCH_REQUESTED
RESEARCH_COMPLETE
PROOF_GUIDANCE_REQUESTED
PROOF_GUIDANCE_GENERATED
COACH_QUERY
COACH_RESPONSE
```

## Configuration

All agents use whatever LLM provider is selected at launch
(`./chainsmith start --profile PROVIDER`). There are no per-agent model
overrides — provider selection is global via `get_llm_client()`.

```yaml
researcher:
  enabled: true
  offline_mode: false          # true for air-gapped networks
  data_sources:                # which external sources to consult
    - nvd
    - exploitdb
    - vendor_advisories

check_proof_advisor:
  enabled: true
  trigger: operator_selected   # operator_selected | auto_verified
  include_commands: true       # generate copy-pasteable proof commands
  include_screenshots: true    # flag screenshot-worthy evidence
  template_dir: app/data/proof_templates/

coach:
  enabled: true
  context_window: summary      # summary | full
  max_recent_events: 50        # how many events to include in context
  memory_cap: 10               # max prior Q&A exchanges retained
```

## Dependencies

- Phases 1-3 persistence (complete) — proof guidance and coach context need
  access to stored session state
- Verifier agent — CheckProofAdvisor operates on verified findings only
- Phase 21 Adjudicator — independent, no integration needed
- Phase 20 Scan Advisor (optional) — Coach directs operators to ScanAdvisor
  for tutoring; no code dependency
