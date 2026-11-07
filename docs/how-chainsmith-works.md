# How Chainsmith Works

Chainsmith is an AI-powered reconnaissance framework for security assessments. It automates the discovery, verification, and analysis of security observations against a target.

This page walks through what happens during a scan, end to end.

## The Lifecycle

**Workspace** — A workspace is a directory that owns everything one body of work produces: the database (scans, observations, verdicts), captured evidence, reports, logs, and per-workspace customizations. Use one workspace per client or project to keep their data physically separate. It is chosen at launch with `--workspace` or `CHAINSMITH_WORKSPACE`; the default is `~/chainsmith/default`.

**Scoping** — Before anything runs, Chainsmith needs to know what it's allowed to touch. The scoping conversation defines in-scope domains, excluded targets, permitted techniques, and an optional time window. The **Guardian** enforces scope throughout the scan — any request to an out-of-scope target is blocked and logged.

**Scan** — A scan is a single execution of the framework against a target. It resolves which checks to run, executes them in dependency order, and collects the results. Scans are stored in the active workspace and produce observations, chains, and reports. Several scans can run at the same time, each with its own session.

The lifecycle runs: scope → scan → grading → verification → chains → adjudication → report.

## What Happens During a Scan

### 1. Check Resolution

Chainsmith selects which checks to run based on the target, the active suites, and any filters you've applied. Checks are grouped into seven **suites** that execute in dependency order:

`network` → `web` → `ai` → `mcp` → `agent` → `rag` → `cag`

Each suite builds on the context produced by the suites before it. Network checks discover services; web checks probe those services; AI/MCP/agent/RAG/CAG checks test for domain-specific vulnerabilities found on those services.

### 2. Check Execution

Each check probes the target and returns a **CheckResult** containing:

- **Candidates** — things the probe found worth judging, handed to the grading stage (below)
- **Services** — new or enriched service information (fed to downstream checks)
- **Errors** — non-fatal problems encountered

Checks declare **conditions** — context keys that must exist before they can run. If a check's conditions aren't met (e.g., no services were discovered), it's skipped.

Every request a check makes can be **captured**: the full exchange — what was sent, what came back, headers, body, timing — written verbatim to the workspace's `evidence/` directory and indexed in the database. Capture is off by default; `--capture` on the CLI (or a `capture` block on the scan API) turns it on for one scan. Nothing in capture interprets anything, and no model is involved.

### 3. Grading

Every check is split along that line into a **probe** (send, record, assert nothing) and a **grade** (re-read the recorded response, place the severity). A probe returns a **candidate** carrying a *provisional* severity; the grading stage turns each candidate into observations, each with a final severity, a **confidence**, the reasoning behind it, and the ids of the exchanges it was graded from.

The grader never touches the network, so the same evidence gives the same verdict during the scan or months afterwards. If grading cannot run, the observation is marked `ungraded` at its provisional severity and the scan continues — a scan never waits on a grader.

Each check declares how its severity is placed in its `contract.yaml`: a fixed severity per kind of observation, or a contextual default and range. When a scan was captured, `chainsmith dev regrade <scan_id>` (a developer command) re-runs the graders over the stored evidence and shows what would change. With `--apply` it writes the new verdicts back; the observations they replace are kept as **superseded** — excluded from counts and risk scores, but listed in the technical report.

### 4. Verification

The **Verifier** agent reviews each observation to catch false positives and hallucinations. It has access to tools that can re-check CVEs, verify versions, and validate endpoints. Each observation gets a status:

- **Verified** — confirmed real
- **Rejected** — false positive
- **Hallucination** — AI-generated error caught

A rejection is a verdict *attached to* an observation, never a reason to delete it. Rejected observations stay in the record and in reports, marked and counted — reports say how many were suppressed and by whom, so a reader who disagrees can see exactly what was set aside.

### 5. Chain Analysis

The **Chainsmith** agent (namesake of the project) looks for observations that combine into attack chains — sequences where individually moderate issues compose into something more severe. Chain discovery uses both rule-based pattern matching and LLM analysis.

### 6. Adjudication

The **Adjudicator** agent challenges severity ratings using an evidence-based rubric. It scores five factors (exploitability, impact, reproducibility, asset criticality, exposure) and may adjust severity up or down. Adjudication is non-destructive — the original severity is always preserved alongside the adjudicated one.

### 7. Reporting

Chainsmith generates reports in multiple formats (Markdown, HTML, PDF, JSON, SARIF, CSV). Report types include:

- **Technical** — full detail with evidence and chains
- **Executive** — high-level summary for stakeholders
- **Delta** — what changed between two scans
- **Compliance** — audit trail and proof of scope
- **Trend** — historical analysis across scans of the same target

## The Components

Chainsmith's pipeline is built from three types of component. See [component taxonomy](component-taxonomy.md) for the full reference.

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

When a critical observation is found, Chainsmith can respond in three ways (`on_critical`, set per check in its `config.yaml` or overridden by a scan preset):

- **Annotate** — flag it, keep going
- **Skip downstream** — skip remaining checks on the affected host
- **Stop** — halt the entire scan

## Proof of Scope

Every outbound request is logged with its scope status. Violations are recorded separately. This creates an auditable trail showing exactly what was tested, when, and whether it was authorized.
