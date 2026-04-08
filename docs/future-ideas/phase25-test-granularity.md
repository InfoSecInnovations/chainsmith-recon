# Phase 25 — Test Granularity: Split Large Test Files

**Depends on:** Phase 24 (Test Suite Reorganization) — **completed**.

Split test files that exceed 500 lines into smaller, single-concern files.
Each new file should cover one logical grouping of tests so that developers
can locate, run, and reason about tests at a glance.

## Baseline

```
pytest tests/ --tb=short -q
1654 passed, 5 skipped, 19 errors (pre-existing in test_preferences_api.py)
```

All waves must reproduce this exact baseline.

## Scope

Many of the original Tier 1 splits from the initial plan have already been
completed. The remaining work covers **8 files totaling ~4,830 lines**,
splitting into an estimated **19 files**. No test logic changes. No new
tests. No deletions.

### Files to Split

| Current file | Lines | Split into | Split strategy |
|---|---|---|---|
| `checks/test_rag_injection.py` | 706 | 2 files | By concern: poisoning/auth (auth bypass, cache, corpus, metadata) vs. vectors/meta (chunk, multimodal, adversarial, resolver, dependencies) |
| `reports/test_reports_sarif.py` | 628 | 3 files | By concern: SARIF report types vs. targeted export tests vs. UI/static file tests |
| `checks/test_mcp_vulnerabilities.py` | 623 | 2 files | By concern: detection (auth, websocket, schema, notification) vs. injection (traversal, template, prompt, sampling) |
| `db/test_db_repositories.py` | 608 | 2 files | By concern: repository CRUD (scan, observation, chain, check log) vs. persist orchestrator |
| `core/test_base_check.py` | 586 | 2 files | By concern: data models (Service, Observation, CheckCondition, enums) vs. execution (BaseCheck, ServiceIteratingCheck) |
| `trend/test_trend.py` | 570 | 2 files | By concern: core metrics (single scan, multi scan, empty cases) vs. engagement/aggregation (engagement trend, override exclusion, averages) |
| `db/test_engagements.py` | 553 | 2 files | By concern: CRUD/relationships (engagement CRUD, scan link) vs. tracking (observation status, scan comparison) |
| `checks/test_ai_leakage.py` | 522 | 2 files | By concern: extraction (prompt leakage, content filter, model info) vs. disclosure (error leakage, history leak, training data) |

### Files Left As-Is

| File | Lines | Reason |
|---|---|---|
| `checks/test_network_banner_grab.py` | 553 | `TestBannerGrabCheckRun` is 376 lines — splitting would require breaking a single class. Tight coupling. |
| `cli/test_cli.py` | 517 | Only 17 lines over threshold. 7 classes are cohesive by CLI command. |

## Implementation Plan

### Wave 1 — Split `checks/` and `reports/` (3 files → 7 files)

**test_rag_injection.py (706 lines) → 2 files:**

```
checks/
├── test_rag_injection.py         # TestAuthBypass, TestCachePoisoning, TestCorpusPoisoning,
│                                 # TestMetadataInjection + shared fixtures
└── test_rag_injection_vectors.py # TestChunkBoundary, TestMultimodalInjection,
                                  # TestAdversarialEmbedding, TestCheckResolverRegistration,
                                  # TestCheckDependencies
```

**test_reports_sarif.py (628 lines) → 3 files:**

```
reports/
├── test_reports_sarif.py          # TestTechnicalReportSARIF, TestDeltaReportSARIF,
│                                  # TestExecutiveReportSARIF, TestComplianceReportSARIF,
│                                  # TestTrendReportSARIF + _create_populated_scan fixture
├── test_reports_targeted.py       # Targeted export standalone tests + targeted_setup fixture
└── test_reports_ui.py             # TestReportsUIPhase8B (static HTML/JS validation)
```

Run full suite. Confirm counts match baseline.

### Wave 2 — Split `checks/` MCP & `db/` Repositories (2 files → 4 files)

**test_mcp_vulnerabilities.py (623 lines) → 2 files:**

```
checks/
├── test_mcp_vulnerabilities.py    # TestMCPAuthCheck, TestWebSocketTransportCheck,
│                                  # TestToolSchemaLeakageCheck, TestMCPNotificationInjectionCheck
│                                  # + shared fixtures
└── test_mcp_injection.py          # TestMCPResourceTraversalCheck, TestResourceTemplateInjectionCheck,
                                   # TestMCPPromptInjectionCheck, TestMCPSamplingAbuseCheck
```

**test_db_repositories.py (608 lines) → 2 files:**

```
db/
├── test_db_repositories.py        # TestScanRepository, TestObservationRepository,
│                                  # TestChainRepository, TestCheckLogRepository + fixtures
└── test_db_orchestrator.py        # TestPersistOrchestrator + mock_state fixture
```

Run full suite. Confirm counts match baseline.

### Wave 3 — Split `core/`, `trend/`, `db/`, `checks/` (4 files → 8 files)

**test_base_check.py (586 lines) → 2 files:**

```
core/
├── test_base_check.py             # TestService, TestObservation, TestCheckCondition,
│                                  # TestSeverity, TestCheckStatus (data models & enums)
└── test_base_check_execution.py   # TestBaseCheck, TestServiceIteratingCheck,
                                   # ConcreteCheck, ConcreteIteratingCheck
```

**test_trend.py (570 lines) → 2 files:**

```
trend/
├── test_trend.py                  # TestSingleScanTrend, TestMultiScanTrend,
│                                  # TestEmptyCases + shared fixtures
└── test_trend_engagement.py       # TestEngagementTrend, TestOverrideExclusion,
                                   # TestAverages
```

**test_engagements.py (553 lines) → 2 files:**

```
db/
├── test_engagements.py            # TestEngagementCRUD, TestScanEngagementLink + fixtures
└── test_engagements_tracking.py   # TestObservationStatusTracking, TestScanComparison
```

**test_ai_leakage.py (522 lines) → 2 files:**

```
checks/
├── test_ai_leakage.py             # TestPromptLeakage*, TestContentFilter*, TestModelInfo*
│                                  # + shared fixtures
└── test_ai_leakage_disclosure.py  # TestAIErrorLeakage*, TestConversationHistoryLeak*,
                                   # TestTrainingDataExtraction*
```

Run full suite. Confirm counts match baseline.

### Wave 4 — Cleanup & Verification

1. Run the full suite one final time.
2. Verify no test was lost: compare total test count against baseline.
3. Verify no file exceeds 500 lines.
4. No CI config updates needed — `ci.yml` and `pyproject.toml` use
   directory-level `tests/` paths only.

## Naming Conventions

- **Keep the original name** for the largest or most "core" portion of the
  split. This minimizes churn in developer muscle memory.
- **Use descriptive suffixes** for the extracted portions:
  `test_rag_injection.py` → `test_rag_injection_vectors.py`, etc.
- **Never use generic suffixes** like `_2.py` or `_part_b.py`.

## Mechanics of Splitting a File

For each file being split:

1. Create the new target files.
2. Move test classes (cut/paste, not copy) from the original into the
   appropriate new file.
3. Copy any file-level imports and module-level fixtures that the moved
   classes need. Do not move fixtures used by classes that remain in the
   original.
4. If a fixture is used by classes in multiple new files, promote it to the
   subdirectory's `conftest.py`.
5. Run `pytest <new_file> -v` to verify the extracted tests pass in isolation.
6. Run `pytest <original_file> -v` to verify the remaining tests still pass.
7. Run `pytest tests/` to verify no cross-file regressions.

## Principles

- **Green-to-green.** Every wave must reproduce the baseline pass/fail count.
- **Move classes, don't rewrite them.** No refactoring test logic. No
  renaming test methods. No changing assertions.
- **Promote fixtures up, never duplicate.** If two new files need the same
  fixture, it goes in `conftest.py`, not in both files.
- **Judgment over formula.** If a file doesn't have a clean split point,
  leave it alone.
- **One wave = one commit.** Each wave is independently revertible.

## Risk & Rollback

- **Low risk.** No test logic changes. Splits are class-level cut/paste
  with import adjustments.
- **Fixture breakage** is the main risk. Mitigated by running the full suite
  after every wave and by promoting shared fixtures to `conftest.py`.
- **Rollback.** `git revert <wave-commit>` restores the previous file
  boundaries with no side effects.

## Success Criteria

- [ ] No split-candidate file exceeds 500 lines
- [ ] `pytest tests/` produces identical pass/fail/skip counts to baseline
- [ ] Every new file is runnable in isolation (`pytest tests/<subdir>/<file>`)
- [ ] No duplicated fixtures — shared fixtures live in `conftest.py`
- [ ] File names describe the concern, not arbitrary numbering
- [ ] Total test count matches baseline — no tests lost or duplicated
