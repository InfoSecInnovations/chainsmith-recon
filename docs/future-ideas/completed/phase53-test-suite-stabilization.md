# Phase 53 — Test Suite Stabilization

**Status:** Proposed
**Prerequisite:** None (independent cleanup)

## Motivation

Full-suite runs (`pytest tests/`) report 10 failures on `main` that are
unrelated to recent feature work. These obscure real regressions during
review and erode trust in CI. Triage shows they fall into three
categories with different fixes.

## Current failures

### A. Order-dependent / test-pollution (6)
Pass in isolation, fail when run as part of the full suite. Likely
cause: a fixture or module-level state that leaks between tests.

- `tests/core/test_check_runner_observations.py::TestServiceHandling::test_services_added_to_context`
- `tests/core/test_check_runner_observations.py::TestServiceHandling::test_duplicate_services_not_added`
- `tests/core/test_check_runner_observations.py::TestServiceHandling::test_service_metadata_merged`
- `tests/core/test_verifier.py::TestVerifierToolExecution::test_verify_cve_tool`
- `tests/core/test_verifier.py::TestVerifierToolExecution::test_verify_cve_hallucination_emits_event`
- `tests/core/test_verifier.py::TestVerifierToolExecution::test_verify_version_tool`
- `tests/core/test_verifier.py::TestVerifierToolExecution::test_verify_endpoint_tool`

### B. Test drift — safe one-line updates (2)
Production code evolved; tests weren't updated.

- `tests/checks/test_mcp.py::TestMCPDiscoveryCheck::test_check_metadata` —
  expects 1 condition; `MCPDiscoveryCheck.conditions` now has 2
  (`services`, `services_probed`).
- `tests/scanning/test_scans_api.py::TestObservationRepositoryReads::test_observation_dict_shape` —
  `target_host` key added to Observation dict; not in `expected_keys`.

### C. Unclear — behavior or test? (1)
- `tests/core/test_on_critical.py::TestLauncherAnnotate::test_annotates_downstream_observations` —
  asserts launcher stamps `raw_data.critical_observation_on_host=True` on
  downstream observations after a critical finding, but `raw_data` is
  empty in the run. Either the annotation feature regressed or was
  never fully shipped. Needs a decision before fixing.

## Sub-phases

| # | Sub-phase | Risk |
|---|-----------|------|
| 53.1 | Fix test drift (B) — update `expected_keys` and condition count assertions. | None — test-only. |
| 53.2 | Root-cause and fix test pollution (A). Bisect to find the polluting test; add proper teardown (likely a module-level registry or global client that needs reset). | Low — test-only if the fix is a fixture; medium if it exposes a real singleton leak in prod code. |
| 53.3 | Investigate on_critical annotation (C). Determine whether `critical_observation_on_host` stamping is implemented; either fix the launcher or drop the assertion. | Unknown until investigated. |

## Open questions

1. **Is `critical_observation_on_host` a shipped feature?** Grep the codebase and recent commits to decide whether 53.3 is a code fix or a test deletion.
2. **Is there a history of flaky CI?** If 53.2 is a longstanding annoyance, prioritize it. If it only manifests locally on Windows, lower priority.
3. **Should `test_scans_live_api.py` be fixed or deleted?** It's currently `--ignore`d because it imports a non-existent `list_live_scans`. Separate from the 10 but same spirit.

## Out of scope

- Broader CI overhaul (test parallelism, coverage gating, pre-commit test runs).
- Adding new test coverage.
- Fixing flakiness in `test_scans_live_api.py` (separate issue).

## Success criteria

- `pytest tests/` exits 0 with no `--deselect` or `--ignore` needed (except `test_scans_live_api.py` if deferred).
- No order-dependent failures when the suite is run repeatedly.
