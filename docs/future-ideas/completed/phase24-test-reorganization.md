# Phase 24 — Test Suite Reorganization

Restructure the flat `tests/` directory into subsystem-aligned subdirectories
so that test files mirror the source layout, each folder is independently
runnable, and fixtures stay close to the code they support.

## Motivation

The test suite has grown to ~28,700 lines across ~40 files. Most sit in a
single flat directory, making it hard to:

- Run only the tests relevant to a change (`pytest tests/` is all-or-nothing
  outside `tests/checks/`)
- Locate the tests that cover a given module
- Keep shared fixtures scoped — everything funnels through the root
  `conftest.py`
- Onboard new contributors who need to understand what is tested where

The `tests/checks/` subdirectory already proves the pattern works well.
This phase extends it to the rest of the suite.

## Target Structure

```
tests/
├── conftest.py                 # global fixtures only (project_root, simulations_dir)
├── checks/                     # ✅ already exists — no changes needed
│   ├── conftest.py
│   ├── test_ai.py
│   ├── test_agent.py
│   ├── test_cag.py
│   ├── test_cag_enhanced.py
│   ├── test_mcp.py
│   ├── test_mcp_enhancements.py
│   ├── test_mcp_phase9.py
│   ├── test_network.py
│   ├── test_network_dns.py
│   ├── test_network_http_methods.py
│   ├── test_network_tls.py
│   ├── test_network_whois.py
│   ├── test_port_profiles.py
│   ├── test_rag.py
│   ├── test_rag_phase13.py
│   ├── test_web.py
│   ├── test_web_favicon.py
│   ├── test_web_header_grading.py
│   ├── test_web_security_exposure.py
│   └── test_web_sitemap.py
├── db/                         # covers app/db/
│   ├── conftest.py             # db session fixtures, temp-db helpers
│   ├── test_db.py              # ← from tests/test_db.py
│   ├── test_engagements.py     # ← from tests/test_engagements.py
│   └── test_profile_store.py   # ← from tests/test_profile_store.py
├── reports/                    # covers app/reports.py and report-adjacent UI
│   ├── conftest.py             # sample findings/scan-result fixtures
│   ├── test_reports.py         # ← from tests/test_reports.py
│   ├── test_reports_ui.py      # ← from tests/test_reports_ui.py
│   ├── test_reports_sarif.py   # ← from tests/test_reports_sarif_export.py
│   └── test_findings_viz.py    # ← from tests/test_findings_viz.py
├── cli/                        # covers app/cli*.py, app/preferences.py
│   ├── conftest.py             # CLI runner fixtures
│   ├── test_cli.py             # ← from tests/test_cli.py
│   ├── test_cli_profiles.py    # ← from tests/test_cli_profiles.py
│   ├── test_preferences.py     # ← from tests/test_preferences.py
│   └── test_preferences_api.py # ← from tests/test_preferences_api.py
├── core/                       # covers engine, config, chain logic
│   ├── conftest.py
│   ├── test_chain.py           # ← from tests/test_chain.py
│   ├── test_base_check.py      # ← from tests/test_base_check.py
│   ├── test_check_runner.py    # ← from tests/test_check_runner.py
│   ├── test_config.py          # ← from tests/test_config.py
│   └── test_on_critical.py     # ← from tests/test_on_critical.py
├── scanning/                   # covers scenarios, simulation, scan advisor
│   ├── conftest.py
│   ├── test_scenarios.py       # ← from tests/test_scenarios.py
│   ├── test_simulated_check.py # ← from tests/test_simulated_check.py
│   ├── test_scan_advisor.py    # ← from tests/test_scan_advisor.py
│   ├── test_scans_api.py       # ← from tests/test_scans_api.py
│   └── test_proof_of_scope.py  # ← from tests/test_proof_of_scope.py
├── llm/                        # covers app/lib/ LLM integration
│   ├── conftest.py
│   ├── test_llm.py             # ← from tests/test_llm.py
│   └── test_payloads.py        # ← from tests/test_payloads.py
└── trend/                      # covers trending / historical analysis
    ├── conftest.py
    └── test_trend.py           # ← from tests/test_trend.py
```

## Implementation Plan

### Wave 1 — Scaffolding & Safety Net

1. **Baseline the current suite.** Run `pytest tests/ --tb=short -q` and
   record the pass/fail/skip counts. This is the reference for the entire
   phase — every wave must reproduce it exactly.

2. **Add `__init__.py` to every new subdirectory.** Create the empty
   directories and init files first, before moving anything.

3. **Audit the root `conftest.py`.** Identify which fixtures are truly
   global (used across multiple subsystems) vs. domain-specific (used only
   by one cluster of test files). Domain-specific fixtures will move into
   subdirectory `conftest.py` files in later waves.

### Wave 2 — Move `reports/` (Biggest Win)

Move the four report-related files (~3,400 lines) into `tests/reports/`.

1. `git mv tests/test_reports.py tests/reports/test_reports.py`
2. `git mv tests/test_reports_ui.py tests/reports/test_reports_ui.py`
3. `git mv tests/test_reports_sarif_export.py tests/reports/test_reports_sarif.py`
4. `git mv tests/test_findings_viz.py tests/reports/test_findings_viz.py`
5. Create `tests/reports/conftest.py` — extract any report-specific fixtures
   from the root conftest.
6. Run full suite. Confirm counts match baseline.

### Wave 3 — Move `db/`

Move the three database-related files (~1,900 lines) into `tests/db/`.

1. `git mv tests/test_db.py tests/db/test_db.py`
2. `git mv tests/test_engagements.py tests/db/test_engagements.py`
3. `git mv tests/test_profile_store.py tests/db/test_profile_store.py`
4. Create `tests/db/conftest.py` — extract DB session / temp-db fixtures.
5. Run full suite. Confirm counts match baseline.

### Wave 4 — Move `cli/`

Move the four CLI-related files (~1,700 lines) into `tests/cli/`.

1. `git mv tests/test_cli.py tests/cli/test_cli.py`
2. `git mv tests/test_cli_profiles.py tests/cli/test_cli_profiles.py`
3. `git mv tests/test_preferences.py tests/cli/test_preferences.py`
4. `git mv tests/test_preferences_api.py tests/cli/test_preferences_api.py`
5. Create `tests/cli/conftest.py` — extract CLI runner fixtures.
6. Run full suite. Confirm counts match baseline.

### Wave 5 — Move `core/`

Move the five core/engine files (~3,100 lines) into `tests/core/`.

1. `git mv tests/test_chain.py tests/core/test_chain.py`
2. `git mv tests/test_base_check.py tests/core/test_base_check.py`
3. `git mv tests/test_check_runner.py tests/core/test_check_runner.py`
4. `git mv tests/test_config.py tests/core/test_config.py`
5. `git mv tests/test_on_critical.py tests/core/test_on_critical.py`
6. Create `tests/core/conftest.py`.
7. Run full suite. Confirm counts match baseline.

### Wave 6 — Move `scanning/`

Move the five scanning-related files (~3,200 lines) into `tests/scanning/`.

1. `git mv tests/test_scenarios.py tests/scanning/test_scenarios.py`
2. `git mv tests/test_simulated_check.py tests/scanning/test_simulated_check.py`
3. `git mv tests/test_scan_advisor.py tests/scanning/test_scan_advisor.py`
4. `git mv tests/test_scans_api.py tests/scanning/test_scans_api.py`
5. `git mv tests/test_proof_of_scope.py tests/scanning/test_proof_of_scope.py`
6. Create `tests/scanning/conftest.py`.
7. Run full suite. Confirm counts match baseline.

### Wave 7 — Move `llm/` and `trend/`

Move the remaining three files into their respective directories.

1. `git mv tests/test_llm.py tests/llm/test_llm.py`
2. `git mv tests/test_payloads.py tests/llm/test_payloads.py`
3. `git mv tests/test_trend.py tests/trend/test_trend.py`
4. Create `tests/llm/conftest.py` and `tests/trend/conftest.py`.
5. Run full suite. Confirm counts match baseline.

### Wave 8 — Slim Down Root `conftest.py`

1. Review the root `conftest.py`. Any fixture used by only one subdirectory
   should move into that subdirectory's `conftest.py`.
2. The root should contain only truly cross-cutting fixtures
   (`project_root`, `simulations_dir`, etc.).
3. Run full suite. Confirm counts match baseline.

### Wave 9 — Add pytest Markers

Add markers for cross-cutting concerns that don't align to folders:

```python
# pytest.ini or pyproject.toml
[tool.pytest.ini_options]
markers = [
    "slow: tests that take >2s (deselect with -m 'not slow')",
    "integration: tests that hit real network, DB, or LLM",
    "unit: pure logic, no I/O",
]
```

Tag existing tests appropriately. This lets CI run `pytest -m 'not slow'`
for fast feedback and the full suite on merge.

### Wave 10 — CI & Documentation

1. Update any CI workflows that reference specific test paths.
2. Update contributing docs or README if they mention test locations.
3. Consider adding a `Makefile` or `pyproject.toml` script aliases:
   - `pytest tests/reports/` — run just report tests
   - `pytest -m unit` — run all fast unit tests
   - `pytest tests/` — run everything

## Principles

- **One wave = one commit.** Each wave is independently revertible.
- **Green-to-green.** Never merge a wave that changes the pass/fail count.
- **Move, don't rewrite.** `git mv` preserves blame history. Do not
  refactor test logic during the move — that is a separate concern.
- **No test deletions.** This phase is purely organizational. Test coverage
  must not decrease.

## Risk & Rollback

- **Low risk.** Every wave is a `git mv` + optional conftest extraction.
  No test logic changes. No source code changes.
- **Rollback.** `git revert <wave-commit>` restores the previous layout
  with no side effects.
- **IDE impact.** Developers may need to re-index after the move. A single
  announcement in the PR description is sufficient.

## Success Criteria

- [ ] All test files live under a subsystem subdirectory (no orphan `test_*.py`
      in the root `tests/` directory)
- [ ] `pytest tests/` produces identical pass/fail/skip counts to baseline
- [ ] `pytest tests/<subdir>/` works for each subdirectory independently
- [ ] Root `conftest.py` contains only cross-cutting fixtures
- [ ] CI pipelines pass without path-related changes (or are updated)
- [ ] pytest markers are registered and CI uses `-m` selectors
