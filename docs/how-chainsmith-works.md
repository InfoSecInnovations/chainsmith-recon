# How Chainsmith Works

Chainsmith is an AI-powered reconnaissance framework for security assessments. It automates the discovery, verification, and analysis of security observations against a target.

This page walks through what happens during a scan, end to end.

## The Lifecycle

**Engagement** — An engagement is the top-level container. It represents a client, project, or ongoing body of work. Engagements hold one or more scans and provide the anchor for trend analysis and compliance reporting. They're optional — you can run scans without one.

**Scoping** — Before anything runs, Chainsmith needs to know what it's allowed to touch. The scoping conversation defines in-scope domains, excluded targets, permitted techniques, and an optional time window. The **Guardian** enforces scope throughout the scan — any request to an out-of-scope target is blocked and logged.

**Scan** — A scan is a single execution of the framework against a target. It resolves which checks to run, executes them in dependency order, and collects the results. A scan belongs to an engagement (or stands alone) and produces observations, chains, and reports.

**flowchart here: lifecycle from engagement → scope → scan → observations → verification → chains → adjudication → report**

## What Happens During a Scan

### 1. Check Resolution

Chainsmith selects which checks to run based on the target, the active suites, and any filters you've applied. Checks are grouped into seven **suites** that execute in dependency order:

`network` → `web` → `ai` → `mcp` → `agent` → `rag` → `cag`

Each suite builds on the context produced by the suites before it. Network checks discover services; web checks probe those services; AI/MCP/agent/RAG/CAG checks test for domain-specific vulnerabilities found on those services.

### 2. Check Execution

Each check follows a stimulus-response pattern: it probes the target, interprets the response, and returns a **CheckResult** containing:

- **Observations** — security-relevant issues discovered
- **Services** — new or enriched service information (fed to downstream checks)
- **Errors** — non-fatal problems encountered

Checks declare **conditions** — context keys that must exist before they can run. If a check's conditions aren't met (e.g., no services were discovered), it's skipped.

### 3. Verification

The **Verifier** agent reviews each observation to catch false positives and hallucinations. It has access to tools that can re-check CVEs, verify versions, and validate endpoints. Each observation gets a status:

- **Verified** — confirmed real
- **Rejected** — false positive
- **Hallucination** — AI-generated error caught

### 4. Chain Analysis

The **Chainsmith** agent (namesake of the project) looks for observations that combine into attack chains — sequences where individually moderate issues compose into something more severe. Chain discovery uses both rule-based pattern matching and LLM analysis.

### 5. Adjudication

The **Adjudicator** agent challenges severity ratings using an evidence-based rubric. It scores five factors (exploitability, impact, reproducibility, asset criticality, exposure) and may adjust severity up or down. Adjudication is non-destructive — the original severity is always preserved alongside the adjudicated one.

### 6. Reporting

Chainsmith generates reports in multiple formats (Markdown, HTML, PDF, JSON, SARIF, CSV). Report types include:

- **Technical** — full detail with evidence and chains
- **Executive** — high-level summary for stakeholders
- **Delta** — what changed between two scans
- **Compliance** — audit trail and proof of scope
- **Trend** — historical analysis across an engagement

## The Components

Chainsmith's pipeline is built from three types of component. See [component taxonomy](future-ideas/component-taxonomy.md) for the full reference.

**Agents** — LLM-powered, autonomous reasoning:

| Agent | Role |
|-------|------|
| **Verifier** | Validates observations, catches hallucinations |
| **Adjudicator** | Evidence-based severity adjudication |
| **Triage** | Prioritized remediation planning |
| **Chainsmith** | Chain validation for custom checks and attack chains |

**Gates** — deterministic policy enforcement:

| Gate | Role |
|------|------|
| **Guardian** | Scope enforcement (continuous, not phase-bound) |

**Advisors** — deterministic post-hoc analysis:

| Advisor | Role |
|---------|------|
| **ScanAdvisor** | Post-scan gap analysis and follow-up recommendations |

## On-Critical Behavior

When a critical observation is found, Chainsmith can respond in three ways (configurable per-suite):

- **Annotate** — flag it, keep going
- **Skip downstream** — skip remaining checks on the affected host
- **Stop** — halt the entire scan

## Proof of Scope

Every outbound request is logged with its scope status. Violations are recorded separately. This creates an auditable trail showing exactly what was tested, when, and whether it was authorized.
