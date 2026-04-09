# Developer Vocabulary

Implementation-level terms and concepts. Assumes familiarity with [Vocabulary](vocabulary.md) and [How Chainsmith Works](how-chainsmith-works.md).

---

## Check Framework

### BaseCheck / ServiceIteratingCheck

The two base classes for checks (`app/checks/base.py`). `BaseCheck` is the general-purpose base. `ServiceIteratingCheck` extends it for checks that need to run once per discovered service — implement `check_service()` instead of `run()`.

### CheckResult

The normalized return type from every check's `run()` method. Contains observations, services, errors, timing data, and an `outputs` dict that gets merged into the shared context.

### CheckCondition

A dependency declaration on a check. Specifies a context key and an operator (`truthy`, `equals`, `contains`, `gte`). The CheckLauncher evaluates these to determine which checks are runnable at any given point.

### CheckLauncher

The execution engine (`app/check_launcher.py`). Runs checks in dependency order, manages the shared context dict, tracks critical hosts, and implements on-critical behavior (annotate/skip/stop).

### CheckLog

An audit record of a check's execution. One per check per scan. Stored in the database with event type (`started`, `completed`, `failed`, `skipped`), duration, observation count, and error details.

### Check Resolver

`app/check_resolver.py` — resolves which checks to instantiate based on suite filters, name filters, and technique filters. Also handles suite inference from check names.

## State & Execution

### AppState

The singleton runtime state object (`app/state.py`). Holds the current session, scan progress, check statuses, skip reasons, settings, and references to the active CheckLauncher and scope checker.

### Session ID

An 8-character hex identifier generated when AppState is created. Links to scan records in the database. Distinct from scan ID — a session can contain multiple scans.

### Context (shared dict)

A mutable dictionary passed through the CheckLauncher. Checks read from it (to get services, upstream results) and write to it (via `CheckResult.outputs`). This is the primary data flow mechanism between checks.

## Database Layer

### Models vs. Pydantic Models

Chainsmith has two parallel model layers:

- **SQLAlchemy models** (`app/db/models.py`) — ORM classes for persistence. These are what gets stored.
- **Pydantic models** (`app/models.py`) — runtime data objects used by agents, the API, and the engine.

The repository layer bridges these — repository methods accept/return dicts, not ORM objects.

### Repositories

Data access layer (`app/db/repositories.py`). Each domain object has a repository with async CRUD methods. Key repositories: `ScanRepository`, `ObservationRepository`, `ChainRepository`, `CheckLogRepository`, `EngagementRepository`, `TrendRepository`, `AdjudicationRepository`.

### Observation Fingerprinting

`SHA-256(check_name | host | title | normalized_evidence)`, truncated to 16 characters. This is how observations are deduplicated across scans and how delta reports classify observations as new, recurring, resolved, or regressed.

### ObservationStatusHistory

Tracks an observation's fingerprint across scans. Enables trend questions like "when did this first appear?" and "has it been resolved before?"

### ObservationOverride

A human override on an observation (accepted or false_positive). Keyed by fingerprint, so it persists across scans.

## Adjudication Internals

### AdjudicatedRisk

The output of the Adjudicator for a single observation. Contains the original severity, adjudicated severity, confidence, rationale, and the five-factor scoring breakdown. Stored alongside but never replacing the original severity.

### AdjudicationApproach

Enum of adjudication methods. Only `EVIDENCE_RUBRIC` is active. Historical values (`STRUCTURED_CHALLENGE`, `ADVERSARIAL_DEBATE`, `AUTO`) exist for database compatibility.

### Severity Weights

Point values used for aggregate risk scoring: critical=100, high=50, medium=25, low=5, info=0.

## Proof of Scope

### TrafficEntry

A logged outbound request with scope status. Types: `HTTP_REQUEST`, `DNS_LOOKUP`, `TOOL_CALL`. Written to `data/traffic_log.jsonl`.

### ViolationEntry

A logged scope violation. Captures the target, the check that triggered it, whether it was blocked, and the reason. Written to `data/violations_log.jsonl`.

### EngagementWindow

An optional time boundary for authorized testing. The scope checker validates that the current time falls within the window before allowing requests.

## Events

### AgentEvent

The event model for the live feed. Each event has a type, source agent, importance level, and optional references to observations/chains. Importance maps to display treatment: `HIGH` (red), `MEDIUM` (yellow), `LOW` (gray).

### EventType

Enum covering the full event taxonomy: agent lifecycle, tool calls, observation discovery/verification/rejection, hallucination detection, chain identification, scope events, adjudication events, and general info/error.

## Swarm (Distributed Execution)

### SwarmTask

A unit of work in the distributed execution model. Wraps a single check with its target info, upstream context, rate limits, and timeout. Progresses through: `QUEUED` → `ASSIGNED` → `IN_PROGRESS` → `COMPLETE`/`FAILED`.

### AgentInfo

A registered swarm agent with capabilities (which suites it can run), concurrency limits, and heartbeat tracking. Status: `ONLINE`, `STALE`, `OFFLINE`.

### CoordinatorStatus

Aggregated view of the swarm: agents online, task counts by status, current phase, total observations.

## Configuration

### ChainsmithConfig

Top-level config object (`app/config.py`). Composed of nested configs: `ScopeConfig`, `LiteLLMConfig`, `PathsConfig`, `StorageConfig`, `SwarmConfig`, `ScanAdvisorConfig`, `AdjudicatorConfig`. Loaded from YAML with environment variable overrides.

### Port Profiles

Preset port ranges: `lab` (common ports), `web` (80/443/8080/8443/etc.), `ai` (inference service ports), `full` (all 65535).

### SeverityOverrideConfig

Allows overriding default severity at the check level or check+title level. Configured in `app/customizations.py`.

## Scan Advisor

### ScanAdvisor

Post-scan recommendation engine (`app/scan_advisor.py`). Produces suggestions based on what was found — gap analysis, config tweaks, seed URLs, speculative checks. Rule-driven via `FOLLOW_UP_RULES`. Recommendations have confidence levels (high/medium/low) and require approval before acting on them.
