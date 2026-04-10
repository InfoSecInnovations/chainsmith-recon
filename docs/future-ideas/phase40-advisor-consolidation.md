# Phase 40 — Advisor Consolidation

## Problem

Advisors are scattered across the codebase with inconsistent placement and
accessibility:

- `CheckProofAdvisor` lives in `app/advisors/check_proof.py` (correct location),
  is routable through chat via keyword matching, and has a `ComponentType` entry.
- `ScanAdvisor` lives in `app/scan_advisor.py` (top-level, not in `app/advisors/`),
  is only reachable via a dedicated REST endpoint (`GET /api/v1/scan-advisor/recommendations`),
  and has no `ComponentType` entry.

Both are deterministic, non-agentic components that produce structured output
from scan data. They should follow the same patterns for location, type system
registration, and chat accessibility.

### Agent vs. Advisor boundary

The dividing line is simple: **agents are LLM-backed** (they have agency),
**advisors are deterministic** (rule-based, no LLM calls). Components like
Coach and Researcher are LLM-backed and belong in `app/agents/`. This phase
does not move or reclassify them.


## Naming convention

All files in `app/advisors/` use the `*_advisor.py` suffix to avoid ambiguity
with other subsystems. For example, `scan_advisor.py` — not `scan.py`, which
would easily be confused with `app/engine/scanner.py`.


## What to do

### 1. Move ScanAdvisor to `app/advisors/`

Move `app/scan_advisor.py` to `app/advisors/scan_advisor.py`. Update all imports:

- `app/routes/advisor.py` — imports ScanAdvisor
- `app/engine/scanner.py` — imports ScanAdvisor (if applicable)
- Any test files that reference the old path

### 2. Add ScanAdvisor to `ComponentType`

After Phase 26 lands the `ComponentType` enum, add:

```python
SCAN_ADVISOR = "scan_advisor"
```

### 3. Make ScanAdvisor chat-accessible

Add keyword patterns to `app/engine/prompt_router.py`:

```python
# Suggested keywords for ScanAdvisor routing
"coverage", "gaps", "what checks", "missed", "scan advice", "recommendations"
```

Add a `_handle_scan_advisor()` method in `app/engine/chat.py` that:
- Retrieves the current scan's check results from the database
- Instantiates `ScanAdvisor` with the scan context
- Calls `analyze()` and formats the recommendations for chat output

The dedicated REST endpoint (`GET /api/v1/scan-advisor/recommendations`)
remains for programmatic and post-scan use.

### 4. Update `app/advisors/__init__.py`

The `__init__.py` already exists with lazy imports for `CheckProofAdvisor`.
Add `ScanAdvisor` to `__all__` and the lazy `__getattr__` loader.


## Scope

This phase is limited to advisor placement and accessibility. It does not:

- Change advisor logic or output formats
- Add new advisors
- Reclassify LLM-backed agents (Coach, Researcher) as advisors
- Modify the prompt router architecture (only adds keyword entries)


## Dependencies

- **Phase 26** (model review) should land first so that `ComponentType` exists
  and the router uses `ComponentType` terminology.
- No other hard dependencies.


## Affected files

**Must change:**
- `app/scan_advisor.py` — move to `app/advisors/scan_advisor.py`
- `app/routes/advisor.py` — update import path
- `app/advisors/__init__.py` — add ScanAdvisor to `__all__` and lazy loader
- `app/engine/prompt_router.py` — add ScanAdvisor keyword patterns
- `app/engine/chat.py` — add `_handle_scan_advisor()` dispatch handler

**Should review:**
- Tests referencing `app.scan_advisor` import path
- `app/engine/scanner.py` — if it imports ScanAdvisor directly
