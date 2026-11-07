# Vocabulary

Core terms used throughout Chainsmith. See [How Chainsmith Works](how-chainsmith-works.md) for how these fit together.

---

### Workspace

A directory that owns everything one body of work produces: the database (scans, observations, verdicts), captured evidence, reports, scratch files, logs, and per-workspace customizations. Use one per client or assessment to keep their data physically separate. Selected at launch with `--workspace` or `CHAINSMITH_WORKSPACE` (default `~/chainsmith/default`), optionally with its own `workspace.yaml` settings. Workspaces replaced the earlier "engagement" grouping.

### Scan

A single execution of the framework against a target. Produces observations, chains, and reports. Tracks its own status (`running`, `complete`, `error`, `cancelled`), timing, and check progress.

### Check

A discrete security test, named with its suite prefix (e.g. `web_header_analysis`). Each check is split into a **probe** that sends traffic and records the response, and a **grade** that reads the recorded response and places severity. Checks declare dependencies (conditions) on context produced by other checks, which determines execution order. Each lives in its own folder with a `contract.yaml` (identity, dependencies, outputs, severity) and a `config.yaml` (tunables).

### Suite

A grouping of related checks. Seven suites execute in dependency order: **network → web → ai → mcp → agent → rag → cag**. Each suite builds on context from the suites before it.

### Observation

A security-relevant issue discovered during a scan. This is the atomic unit of Chainsmith's output — everything downstream (verification, chaining, adjudication, reporting) operates on observations.

Each observation has a **severity**, a **status**, a **confidence** score, and **evidence**.

### Severity

How serious an observation is. Five levels:

| Level | Meaning |
|-------|---------|
| **Critical** | Immediate exploitation risk |
| **High** | Significant security issue |
| **Medium** | Notable issue worth attention |
| **Low** | Minor issue |
| **Info** | Informational, no direct risk |

### Status (Observation)

The verification state of an observation:

- **Pending** — awaiting verification
- **Verified** — confirmed by the Verifier
- **Rejected** — determined to be a false positive
- **Hallucination** — AI-generated error caught by the Verifier

### Chain (Attack Chain)

A combination of observations that together represent a more severe attack path than any individual observation alone. Chains have their own **combined severity** that can exceed the severity of their component observations.

Discovered through rule-based pattern matching and LLM analysis.

### Adjudication

The process of challenging an observation's severity using an evidence-based rubric. Scores five factors: exploitability, impact, reproducibility, asset criticality, and exposure. May adjust severity up or down. Non-destructive — the original severity is always preserved.

### Scope

The boundary of authorized testing. Defines in-scope domains, exclusions, permitted techniques, forbidden techniques, and an optional time window. Enforced continuously by the Guardian.

### Component Types

Chainsmith's pipeline uses three types of internal component. See [component taxonomy](component-taxonomy.md) for the full reference.

- **Agent** — LLM-powered, autonomous reasoning. Outputs carry uncertainty and require audit trails. Examples: Verifier, Adjudicator, Triage, Chainsmith.
- **Gate** — Deterministic policy enforcement. Makes binary pass/fail decisions. Trusted implicitly. Example: Guardian.
- **Advisor** — Deterministic post-hoc analysis. Reads completed state, produces recommendations, never blocks. Example: ScanAdvisor.

### Guardian

A **Gate** responsible for scope enforcement. Every outbound request is checked against the scope definition. Out-of-scope requests are blocked and logged as violations. Also enforces the scope's optional time window.

### Verifier

An **Agent** that validates observations after scanning. Uses tools (CVE lookup, version verification, endpoint probing) to catch false positives and hallucinations. Each observation receives a status (verified, rejected, hallucination) and a confidence score.

### Adjudicator

An **Agent** that challenges severity ratings using a CVSS-like evidence rubric. Scores exploitability, impact, reproducibility, asset criticality, and exposure. May adjust severity up or down. Non-destructive — the original severity is always preserved.

### Triage

An **Agent** that produces prioritized remediation action plans from adjudicated observations and attack chains. Considers team context (size, velocity, remediation surface) to generate effort/impact-scored workstreams.

### ScanAdvisor

An **Advisor** that analyzes completed scan state. Identifies checks that couldn't run (gap analysis), checks that failed (partial results), checks worth running next (follow-up suggestions), and suites with insufficient coverage. Optional, disabled by default.

### Fingerprint

A stable identifier for an observation, computed from its check name, host, title, and key evidence. Used to track observations across scans — this is how Chainsmith knows whether an observation is new, recurring, resolved, or regressed.

### Profile

A saved configuration (scope, suites, techniques, settings) that can be reloaded for consistent repeat scans.

### Scenario

A simulated target environment defined in YAML. Used for testing and demonstration without a live target.

### Service

A discovered network service (host + port + type). Services are the connective tissue between suites — network checks discover them, and downstream checks consume them.

### Capture line

The rule the evidence and grading design is built on: **fact below, judgment above.** Below the line — what was sent, what came back, what scope allowed, and what an agent sent to a model — is recorded verbatim with no model involved. Above the line — what a response *means*, how severe it is, what to try next — is judgment, carries provenance, and is human-overridable. No model may ever remove anything from the record.

### Evidence

One recorded **exchange**: a request/response pair in whatever protocol the check speaks (`http`, `dns`, `tcp`, `tls`, `whois`, `local`, `llm`, `traceroute`), with headers, bodies, status, timing, and two hashes. The document lives on disk under the workspace's `evidence/<scan_id>/`; the `evidence` table indexes it. Redacted by default on read; capture is off unless a scan asks for it (`--capture`).

### probe_hash / content_hash

The two hashes on an exchange, answering two different questions. **`probe_hash`** covers the request — *"is this the same probe?"*, which is what groups repeat samples of one stimulus. **`content_hash`** covers the request and response together — *"is this the same evidence?"*, which is what makes a verdict cacheable and a stored body verifiable. Both are computed after normalising volatile values (uuids, timestamps, epochs) so a stable target does not hash differently every run.

### Candidate

What a **probe** emits: a subject to be graded. Everything an observation has except the verdict and the confidence, plus a *provisional* severity. An observation is a graded candidate.

### Provisional severity

The severity a candidate carries before a grader has placed one. It is what the launcher's `on_critical` reads when grading is deferred or fails, and it is kept on the graded observation alongside the final value — *"provisional low, graded high"* is inspectable rather than a silent overwrite. Never presented as a verdict.

### Verdict

What a **grader** returns for one judgement: a severity, a **confidence**, the reasoning behind it, the signals it weighed, and the ids of the exchanges it was derived from. One candidate may yield several verdicts — a single HTTP response carries several independent judgements.

### Grading state / tier

State is per observation, never per scan: `ungraded`, `graded`, or `grading_failed` — plus `superseded`, set only by an offline re-grade (`chainsmith dev regrade --apply`) on a placeholder whose candidate now grades under different ids. A superseded row is kept, never deleted, but it is **left out of every count, risk score, comparison and trend** (its successor is already counted). Reports state how many there are, and the API returns them only with `include_superseded=true`. A scan never waits on a grader and never drops a candidate because of one. Tier says who graded it — `rule` (deterministic, the entire air-gapped story) or `llm`.

### Reproducible (not deterministic)

The property the evidence programme targets. Three parts: **byte-identical replay** (the same evidence re-derives the same verdict), **stable verdicts against a stochastic target** (reached by sampling), and **auditable traceability** (every verdict traces back to recorded evidence). "Deterministic" is the wrong word for a system whose targets include language models, and is reserved for Guardian, which genuinely is one.

### Workspace

The directory that owns one body of work: its database, evidence, reports, logs, and customizations, with a `workspace.yaml` stating defaults once. Selected at launch (`--workspace`, `CHAINSMITH_WORKSPACE`, or `workspace:` in config), defaulting to `~/chainsmith/default/`. It is what gives retention, encryption scope, client separation, and corpus portability a container instead of a foreign key.

### Operator Context

Operator-declared metadata about target assets (exposure level, criticality). Fed to the Adjudicator to inform severity decisions. Configured via `~/.chainsmith/adjudicator_context.yaml`.

### Datetime handling

All internal datetimes are timezone-aware UTC. Convert to operator-local time only at display boundaries (reports, UI). Use `app.lib.timeutils` helpers (`now_utc`, `iso_utc`, `parse_iso_utc`) instead of `datetime.utcnow()` or bare `datetime.now()`.
