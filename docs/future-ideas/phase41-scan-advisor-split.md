# Phase 41: Scan Advisor Split

## Overview

Split the current `ScanAdvisor` into two distinct advisors with clear
temporal boundaries:

- **ScanAnalysisAdvisor** (rename of existing ScanAdvisor) — post-scan
  analysis: gap analysis, partial results, follow-ups, coverage
- **ScanPlannerAdvisor** (new) — pre-scan planning: scope completeness,
  check selection guidance, engagement readiness

## Motivation

The current `ScanAdvisor` only operates post-scan, but there is a
clear need for pre-scan guidance — especially for Guided Mode
(Phase 36), where operators benefit from proactive scope and planning
suggestions before they hit "scan."

Today, scope-related questions route to Chainsmith via the
PromptRouter, but Chainsmith doesn't own scope anymore. It manages
the check ecosystem and attack chains. Phase 36 temporarily routes
scope questions to Coach as an interim measure. This phase creates
the proper long-term home for pre-scan planning.

The rename of `ScanAdvisor` to `ScanAnalysisAdvisor` clarifies what
it actually does — post-scan analysis — and prevents confusion now
that there are two scan-related advisors.

## Design

### Component taxonomy

Both components are **advisors** (deterministic, rule-based, no LLM).
They analyze state and produce recommendations. They never execute
checks or modify scope directly.

```
Advisors
  +-- ScanAnalysisAdvisor  (post-scan, renamed from ScanAdvisor)
  +-- ScanPlannerAdvisor   (pre-scan, new)
  +-- CheckProofAdvisor    (existing, unchanged)
```

### ScanAnalysisAdvisor (rename)

No functional changes. This is a rename of the existing `ScanAdvisor`
to reflect its actual responsibility: post-scan analysis.

**Rename scope:**
- `app/advisors/scan_advisor.py` -> `app/advisors/scan_analysis_advisor.py`
- Class: `ScanAdvisor` -> `ScanAnalysisAdvisor`
- Config: `ScanAdvisorConfig` -> `ScanAnalysisAdvisorConfig`
- Recommendation: `ScanAdvisorRecommendation` -> `ScanAnalysisRecommendation`
- Factory: `build_advisor_from_launcher` -> `build_analysis_advisor_from_launcher`
- ComponentType: `SCAN_ADVISOR` -> `SCAN_ANALYSIS_ADVISOR`
- All imports, references, PromptRouter keywords, routes, tests

### ScanPlannerAdvisor (new)

Pre-scan advisor that analyzes the current scope, target
characteristics, and available checks to produce planning
recommendations before the operator starts scanning.

**Responsibilities:**
- **Scope completeness** — Flag missing exclusions, suggest common
  out-of-scope patterns based on target type (e.g., third-party
  CDNs, login portals for shared services)
- **Check selection guidance** — Based on scope and target
  characteristics, recommend which suites and checks are most
  relevant
- **Engagement readiness** — Verify that scope is set, proof-of-scope
  is configured (if required), and prerequisites are met before
  scanning
- **Target analysis** — Identify target characteristics (API-heavy,
  LLM-powered, traditional web app) and suggest appropriate check
  strategies

**What it does NOT do:**
- Modify scope directly (advisor only — recommends, operator decides)
- Execute checks
- Use LLM (deterministic rules, like ScanAnalysisAdvisor)

**Data model:**

```python
@dataclass
class ScanPlannerRecommendation:
    category: str       # scope_completeness, check_selection, readiness, target_analysis
    reason: str
    suggestion: str     # actionable recommendation
    confidence: str     # high, medium, low
    auto_fixable: bool  # can the system apply this automatically if operator approves?
    fix_action: dict | None = None  # e.g., {"add_exclusion": "cdn.example.com"}
```

**Input:**
- Current scope definition (in-scope domains, exclusions)
- Available checks and suites
- Proof-of-scope configuration
- Target characteristics (derived from scope domains)

**Rules (initial set):**

| Rule | Category | Trigger | Confidence |
|------|----------|---------|------------|
| No exclusions defined | scope_completeness | `len(out_of_scope_domains) == 0` | medium |
| Common CDN/third-party in scope | scope_completeness | In-scope domain resolves to known CDN | high |
| No proof-of-scope configured | readiness | Proof-of-scope disabled and scope has external targets | medium |
| AI suite available but no AI checks selected | check_selection | Target has API endpoints but AI suite not selected | medium |
| Engagement window not set | readiness | No time window defined for scope | low |
| Single domain, broad port range | target_analysis | One domain with all-ports profile | low |

Rules are extensible — new rules can be added without changing the
advisor architecture.

**Integration points:**

```python
class ScanPlannerAdvisor:
    def __init__(
        self,
        scope: ScopeDefinition,
        available_checks: set[str],
        check_metadata: dict[str, dict],
        proof_of_scope_config: dict,
    ):
        ...

    def analyze(self) -> list[ScanPlannerRecommendation]:
        """Run all pre-scan planning rules."""
        ...
```

### PromptRouter migration

Phase 36 temporarily routes scope keywords to Coach. This phase
moves them to their permanent home:

**Before (Phase 36 interim):**
```python
(re.compile(r"\b(scope|target|exclude|exclusion|timeframe)\b", re.I), ComponentType.COACH),
```

**After (Phase 41):**
```python
(re.compile(r"\b(scope|target|exclude|exclusion|timeframe)\b", re.I), ComponentType.SCAN_PLANNER_ADVISOR),
```

Coverage/gap keywords also update:
```python
# Before
(re.compile(r"\b(coverage|gaps|missed)\b", re.I), ComponentType.SCAN_ADVISOR),

# After
(re.compile(r"\b(coverage|gaps|missed)\b", re.I), ComponentType.SCAN_ANALYSIS_ADVISOR),
```

### Guided Mode integration (Phase 36)

When Phase 41 lands, the Phase 36 `scope_incomplete` proactive
trigger migrates from Coach to ScanPlannerAdvisor:

```python
# Phase 36 interim
{"trigger": "scope_incomplete", "agent": "coach"}

# Phase 41 permanent
{"trigger": "scope_incomplete", "agent": "scan_planner_advisor"}
```

ScanPlannerAdvisor can also emit additional guided-mode triggers:

| Trigger | Message |
|---------|---------|
| `scope_incomplete` | "Your scope is missing exclusions — want suggestions?" |
| `engagement_not_ready` | "Proof-of-scope isn't configured yet. Want to set it up?" |
| `suite_suggestion` | "This target looks AI-heavy — consider enabling the AI suite." |

## Sub-Phases

### Sub-Phase 41a — Rename ScanAdvisor to ScanAnalysisAdvisor

Mechanical rename. No functional changes.

- Rename file: `scan_advisor.py` -> `scan_analysis_advisor.py`
- Rename classes, config, recommendation, factory function
- Update `ComponentType` enum
- Update all imports (scanner.py, routes, tests)
- Update PromptRouter keyword routing
- Update any references in docs

### Sub-Phase 41b — Implement ScanPlannerAdvisor

New component.

- Create `app/advisors/scan_planner_advisor.py`
- Define `ScanPlannerRecommendation` data model
- Implement initial rule set (scope completeness, readiness, check selection)
- Add `SCAN_PLANNER_ADVISOR` to `ComponentType` enum
- Add API route for triggering pre-scan planning analysis
- Update PromptRouter: scope keywords route to ScanPlannerAdvisor
- Wire into Guided Mode proactive triggers (migrate from Coach)
- Integrate with scope page UI (show recommendations before scan)

### Sub-Phase dependencies

```
41a ──> 41b
```

41b depends on 41a because the rename establishes the naming
convention and clears the "ScanAdvisor" name from ambiguity.

## Dependencies

- Phase 36 (Guided Mode) — ScanPlannerAdvisor inherits the
  `scope_incomplete` trigger from Coach [SHOULD BE DONE FIRST]
- Phase 20 (Scan Advisor) — the component being renamed [DONE]
- Existing scope system (routes/scope.py, guardian.py) [DONE]

## What This Is NOT

- **Not a scope manager.** ScanPlannerAdvisor recommends, it doesn't
  modify scope. The operator always decides.
- **Not LLM-powered.** Both advisors are deterministic and rule-based,
  consistent with the existing advisor taxonomy.
- **Not a replacement for Guardian.** Guardian enforces scope at
  runtime. ScanPlannerAdvisor advises on scope quality before scanning.
