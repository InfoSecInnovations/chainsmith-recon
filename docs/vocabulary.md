# Vocabulary

Core terms used throughout Chainsmith. See [How Chainsmith Works](how-chainsmith-works.md) for how these fit together.

---

### Engagement

A project-level container grouping related scans. Represents a client, assessment, or ongoing body of work. Scans can exist without one, but engagements enable trend analysis and compliance reporting across multiple scans.

### Scan

A single execution of the framework against a target. Produces observations, chains, and reports. Tracks its own status (`running`, `complete`, `error`, `cancelled`), timing, and check progress.

### Check

A discrete security test. Each check follows a stimulus-response pattern: probe the target, interpret the response, report what was found. Checks declare dependencies (conditions) on context produced by other checks, which determines execution order.

### Suite

A grouping of related checks. Seven suites execute in dependency order: **network → web → ai → mcp → agent → rag → cag**. Each suite builds on context from the suites before it.

### Observation

A security-relevant issue discovered during a scan. This is the atomic unit of Chainsmith's output — everything downstream (verification, chaining, adjudication, reporting) operates on observations.

Each observation has a **severity**, a **status**, a **confidence** score, and **evidence**.

> Formerly called "Finding" — renamed in Phase 30.

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

### Guardian

The agent responsible for scope enforcement. Every outbound request is checked against the scope definition. Out-of-scope requests are blocked and logged as violations.

### Fingerprint

A stable identifier for an observation, computed from its check name, host, title, and key evidence. Used to track observations across scans — this is how Chainsmith knows whether an observation is new, recurring, resolved, or regressed.

### Profile

A saved configuration (scope, suites, techniques, settings) that can be reloaded for consistent repeat scans.

### Scenario

A simulated target environment defined in YAML. Used for testing and demonstration without a live target.

### Service

A discovered network service (host + port + type). Services are the connective tissue between suites — network checks discover them, and downstream checks consume them.

### Evidence

Raw data captured during a check: request/response pairs, headers, status codes, response times. Attached to observations to support verification and reporting.

### Operator Context

Operator-declared metadata about target assets (exposure level, criticality). Fed to the Adjudicator to inform severity decisions. Configured via `~/.chainsmith/adjudicator_context.yaml`.
