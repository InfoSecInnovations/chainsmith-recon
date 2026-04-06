# Phase 22 — Verification Enhancements, Proof Advisor & Coach

Three complementary changes that strengthen how findings are validated,
contextualized, and explained to operators.

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

Proof Advisor keys off this field to decide how much reproduction guidance
the operator needs.

### Richer verification_notes

Current `verification_notes` are terse and LLM-facing. Expand them slightly
so downstream agents (Proof Advisor, Adjudicator) and the operator get more
signal without changing the Verifier's role.

Before: `"CVE-2021-41773 confirmed in NVD"`
After:  `"CVE-2021-41773 exists in NVD. Published 2021-10-05, CVSS 7.5. Affects Apache 2.4.49-2.4.50. ScanAdvisor's claimed version (2.4.49) falls within the affected range."`

### No new responsibilities

Verifier stays a gate. It does not contextualize, teach, or advise. It
validates and stamps.


## 2. Proof Advisor (new agent)

Sits after Verifier in the pipeline. Takes verified findings and helps the
operator independently confirm them and build report-quality evidence.

### Core responsibilities

- **Reproduction steps** — exact commands (curl, nmap, Burp) to independently
  confirm the finding.
- **Evidence checklist** — what a complete write-up needs (raw response capture,
  screenshot with timestamp, version-to-CVE mapping).
- **Severity justification** — why this severity holds up given the context,
  or flags where it might not.
- **False positive indicators** — what would make this finding not real, so the
  operator knows what to look for.

### Tools

Proof Advisor calls tools, but only read-oriented ones:

- Re-probe an endpoint to generate a copy-pasteable proof command
- Look up a CVE to explain impact and affected versions
- Fetch raw evidence from session state

It never discovers new things. It works with what Verifier already stamped.

### Pipeline position

```
ScanAdvisor -> Verifier -> Proof Advisor -> Chainsmith
```

### Triggering

Operator-selected, not automatic. The operator picks which findings they want
proof guidance for. This keeps it practical — not every Info-severity header
disclosure needs a proof walkthrough.

### Output model

```
ProofGuidance:
  finding_id: str
  finding_title: str
  verification_status: str              # from Verifier

  manual_proof:
    tool: str                           # curl, nmap, burp, browser, etc.
    command: str                        # exact command to run
    expected_output: str                # what confirms the finding
    screenshot_worthy: bool

  evidence_checklist:
    - description: str
      captured: bool                    # false = operator still needs this

  severity_rationale: str               # why this severity, in context

  false_positive_indicators: list[str]  # what would disprove this

  common_mistakes: list[str]            # pitfalls when verifying this type
```

### Relationship to Phase 21 (Adjudicator)

Adjudicator debates whether the severity is *accurate*. Proof Advisor helps
the operator *prove the finding exists*. They complement each other:

- Adjudicator says: "This is Medium, not High, because it requires local
  network access."
- Proof Advisor says: "Here's the curl command to confirm the header is
  present, and here's what your report evidence section should include."

If both are active, Proof Advisor should consume the Adjudicator's
`adjudicated_severity` rather than ScanAdvisor's original severity for its
rationale section.


## 3. Coach (new agent)

An always-available conversational agent that explains anything happening
inside Chainsmith. No tools. Pure LLM conversation grounded in session
context.

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

### System prompt character

- Plain language, no jargon-for-jargon's-sake
- Adjusts depth to the question — one-liner for "what does CORS mean?",
  detailed walkthrough for "explain this chain's impact"
- References specific findings by ID when relevant ("F-003 shows the Server
  header returning Apache/2.4.49 — that version number is the key piece
  because...")
- Never speculates about findings it can't see in the session context


## New model entries

```python
class AgentType(str, Enum):
    SCAN_ADVISOR = "scan_advisor"
    VERIFIER = "verifier"
    CHAINSMITH = "chainsmith"
    GUARDIAN = "guardian"
    PROOF_ADVISOR = "proof_advisor"
    COACH = "coach"
```

## New events

```
PROOF_GUIDANCE_REQUESTED
PROOF_GUIDANCE_GENERATED
COACH_QUERY
COACH_RESPONSE
```

## Configuration

```yaml
proof_advisor:
  enabled: true
  trigger: operator_selected    # operator_selected | auto_verified
  include_commands: true        # generate copy-pasteable proof commands
  include_screenshots: true     # flag screenshot-worthy evidence

coach:
  enabled: true
  context_window: summary       # summary | full
  max_recent_events: 50         # how many events to include in context
```

## Open questions

- **Coach memory:** Should Coach remember prior questions within a session so
  the operator can have a multi-turn conversation? ("What about F-005?" after
  asking about F-003.) Likely yes, but adds state management.
- **Coach in training mode:** In scenario/training contexts, Coach could
  proactively hint at what the operator should investigate next. This overlaps
  with the Scan Advisor's tutor mode (Phase 20, open question 3) — may want
  to unify these.
- **Proof Advisor for chains:** Should Proof Advisor generate proof guidance
  for entire attack chains (multi-step reproduction), or only individual
  findings? Chain-level proof is harder but more valuable for reports.
- **LLM selection:** Coach and Proof Advisor have very different cost profiles.
  Coach is conversational and latency-sensitive (smaller/faster model). Proof
  Advisor needs technical precision (larger model, fewer calls). Consider
  separate model configs like Verifier already has.

## Dependencies

- Phases 1-3 persistence (complete) — proof guidance and coach context need
  access to stored session state
- Verifier agent — Proof Advisor operates on verified findings only
- Phase 21 Adjudicator (optional) — Proof Advisor can consume adjudicated
  severity if available
- Phase 20 Scan Advisor (optional) — Coach's tutor mode overlaps with Scan
  Advisor's tutor mode; coordinate if both are built
