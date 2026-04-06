# Phase 25 — Test Granularity: Split Large Test Files

**Depends on:** Phase 24 (Test Suite Reorganization) — files must be in
their subdirectories before splitting.

Split the 28 test files that exceed 500 lines into smaller, single-concern
files. Each new file should cover one logical grouping of tests so that
developers can locate, run, and reason about tests at a glance.

## Motivation

After Phase 24 moves files into subsystem directories, many of those files
remain monolithic. A 1,300-line test file covering 16 different classes
is hard to navigate, slow to mentally parse, and discourages targeted test
runs. Smaller files mean:

- Faster feedback — run only the 80-line file that covers the code you
  changed, not the 1,300-line file that covers the whole subsystem
- Clearer ownership — diffs touch fewer unrelated tests
- Better failure triage — the file name alone tells you what broke
- Easier review — PRs that add tests to a focused file are simpler to
  evaluate

## Scope

28 files totaling ~19,000 lines will be split into an estimated 80–90
smaller files. No test logic changes. No new tests. No deletions.

### Tier 1 — Files Over 1,000 Lines (10 files, ~11,500 lines)

These are the highest priority. Each contains many distinct test classes
that map cleanly to separate concerns.

| Current file | Lines | Split into | Split strategy |
|---|---|---|---|
| `checks/test_ai.py` | 1,371 | 4 files | By concern: endpoint discovery, framework fingerprinting, leakage (prompt/error/history), attacks (auth bypass, adversarial, guardrails, caching) |
| `test_findings_viz.py` | 1,337 | 4 files | By visualization type: heatmap, radar, coverage, timeline |
| `checks/test_rag_phase13.py` | 1,226 | 3 files | By concern: storage (vector store, collections), retrieval (manipulation, reranking, fusion), injection (metadata, corpus, embedding, multimodal) |
| `test_reports.py` | 1,173 | 5 files | By report type: technical, delta, executive, compliance, trend |
| `checks/test_mcp_enhancements.py` | 1,144 | 3 files | By concern: discovery (fingerprint, version), vulnerabilities (auth, injection, traversal, sampling), controls (rate limit, capabilities) |
| `checks/test_network_http_methods.py` | 1,048 | 2 files | By check: HTTP method enumeration, banner grabbing |
| `checks/test_network_whois.py` | 1,040 | 3 files | By check: WHOIS lookup, traceroute, IPv6 discovery |
| `checks/test_web_sitemap.py` | 951 | 4 files | By check: sitemap, redirect chain, error page, SSRF indicator |
| `checks/test_web_favicon.py` | 887 | 3 files | By concern: fingerprinting (favicon, HTTP/2), content security (HSTS, SRI), API vulnerabilities (mass assignment) |
| `checks/test_agent_phase12.py` | 870 | 4 files | By wave: discovery/fingerprinting, active exploitation, framework-specific/memory, multi-agent attacks |

### Tier 2 — Files 500–1,000 Lines (18 files, ~11,200 lines)

Lower priority. Many of these are already reasonably focused, but some
contain distinct logical sections that would benefit from splitting.

| Current file | Lines | Split into | Split strategy |
|---|---|---|---|
| `test_scenarios.py` | 796 | 2–3 files | By scenario category (if distinct groups exist) |
| `test_db.py` | 775 | 2 files | By concern: schema/migrations vs. CRUD operations |
| `checks/test_web_header_grading.py` | 775 | 2 files | By concern: header detection vs. grading logic |
| `test_simulated_check.py` | 758 | 2 files | By concern: simulation setup vs. result validation |
| `test_check_runner.py` | 698 | 2 files | By concern: runner orchestration vs. individual check dispatch |
| `test_reports_sarif_export.py` | 665 | Keep as-is or 2 files | Already single-format; split only if distinct sections |
| `test_proof_of_scope.py` | 659 | 2 files | By concern: scope validation logic vs. API/CLI integration |
| `checks/test_web_security_exposure.py` | 633 | 2 files | By concern: exposure detection vs. finding generation |
| `checks/test_network.py` | 619 | 2 files | By check type if multiple checks are covered |
| `checks/test_cag_enhanced.py` | 660 | 2 files | By concern: CAG logic vs. enhanced features |
| `checks/test_network_dns.py` | 651 | 2 files | By concern: DNS resolution vs. DNS security findings |
| `checks/test_network_tls.py` | 863 | 2–3 files | By concern: TLS handshake, certificate validation, cipher analysis |
| `checks/test_web.py` | 688 | 2 files | By check if multiple web checks are covered |
| `test_base_check.py` | 582 | Keep as-is or 2 files | Split only if clearly separate concerns |
| `test_trend.py` | 566 | Keep as-is or 2 files | Split only if clearly separate concerns |
| `test_engagements.py` | 547 | Keep as-is or 2 files | Split only if CRUD vs. lifecycle are distinct |
| `test_cli.py` | 515 | 2 files | By concern: command parsing vs. output formatting |
| `test_config.py` | 500 | Keep as-is | Borderline — only split if obvious groupings |

**Note:** Tier 2 files marked "Keep as-is" should be reviewed during
execution. If they have clean split points, split them. If the split
would be awkward or arbitrary, leave them alone.

## Implementation Plan

### Wave 1 — Baseline & Shared Fixture Audit

1. Run `pytest tests/ --tb=short -q` and record pass/fail/skip counts.
   This is the reference for the entire phase.

2. For each subdirectory, review the `conftest.py` to understand which
   fixtures exist and which test files use them. Splitting files must not
   break fixture resolution.

### Wave 2 — Split `reports/` Tests (Tier 1)

Split `test_reports.py` (1,173 lines, 25 classes) into five files by
report type:

```
reports/
├── test_report_technical.py    # TestTechnicalReport* classes
├── test_report_delta.py        # TestDeltaReport* classes
├── test_report_executive.py    # TestExecutiveReport* classes
├── test_report_compliance.py   # TestComplianceReport* classes
└── test_report_trend.py        # TestTrendReport* classes
```

Split `test_findings_viz.py` (1,337 lines, 16 classes) into four files
by visualization type:

```
reports/
├── test_viz_heatmap.py         # TestHeatmap* classes
├── test_viz_radar.py           # TestRadar* classes
├── test_viz_coverage.py        # TestCoverage* classes
└── test_viz_timeline.py        # TestTimeline* classes
```

Run full suite. Confirm counts match baseline.

### Wave 3 — Split `checks/` AI & RAG Tests (Tier 1)

Split `test_ai.py` (1,371 lines) into four files:

```
checks/
├── test_ai_endpoints.py        # Endpoint & embedding discovery
├── test_ai_fingerprint.py      # Framework & model behavior fingerprinting
├── test_ai_leakage.py          # Prompt, error, history, training data leakage
└── test_ai_attacks.py          # Auth bypass, adversarial, guardrails, caching
```

Split `test_rag_phase13.py` (1,226 lines) into three files:

```
checks/
├── test_rag_storage.py         # Vector store access, collection enum, embedding fingerprint
├── test_rag_retrieval.py       # Retrieval manipulation, source attribution, fusion/reranker
└── test_rag_injection.py       # Cache/corpus poisoning, metadata/multimodal injection, adversarial embedding
```

Run full suite. Confirm counts match baseline.

### Wave 4 — Split `checks/` MCP & Agent Tests (Tier 1)

Split `test_mcp_enhancements.py` (1,144 lines) into three files:

```
checks/
├── test_mcp_discovery.py       # Server fingerprint, protocol version
├── test_mcp_vulnerabilities.py # Auth, injection, traversal, sampling abuse
└── test_mcp_controls.py        # Rate limiting, undeclared capabilities, invocation safety
```

Split `test_agent_phase12.py` (870 lines) into four files:

```
checks/
├── test_agent_discovery.py     # Multi-agent detection, framework version, memory extraction
├── test_agent_exploitation.py  # Tool abuse, privilege escalation, loop/callback/streaming injection
├── test_agent_framework.py     # Framework exploits, memory poisoning, context overflow, reflection, state
└── test_agent_multiagent.py    # Trust chain, cross-injection, registration
```

Run full suite. Confirm counts match baseline.

### Wave 5 — Split `checks/` Network Tests (Tier 1)

Split `test_network_http_methods.py` (1,048 lines) into two files:

```
checks/
├── test_network_http_methods.py  # HTTP method enumeration (keep name)
└── test_network_banner_grab.py   # Banner grabbing, service ID, Redis auth
```

Split `test_network_whois.py` (1,040 lines) into three files:

```
checks/
├── test_network_whois.py       # WHOIS lookup, parsing, domain/ASN findings (keep name)
├── test_network_traceroute.py  # Traceroute, CDN detection, hop probing
└── test_network_ipv6.py        # IPv6 discovery, AAAA resolution, findings
```

Run full suite. Confirm counts match baseline.

### Wave 6 — Split `checks/` Web Tests (Tier 1)

Split `test_web_sitemap.py` (951 lines) into four files:

```
checks/
├── test_web_sitemap.py         # Sitemap discovery and parsing (keep name)
├── test_web_redirect.py        # Redirect chain analysis
├── test_web_error_page.py      # Error page framework detection
└── test_web_ssrf.py            # SSRF indicator detection
```

Split `test_web_favicon.py` (887 lines) into three files:

```
checks/
├── test_web_favicon.py         # Favicon hashing, HTTP/2 detection (keep name)
├── test_web_hsts_sri.py        # HSTS preload, subresource integrity
└── test_web_mass_assignment.py # Mass assignment vulnerability
```

Run full suite. Confirm counts match baseline.

### Wave 7 — Tier 2 Splits (Selective)

Work through Tier 2 files. For each file:

1. Read the file and identify class groupings.
2. If there are 2+ clearly distinct concerns with 200+ lines each, split.
3. If the file is cohesive or the split would be forced, leave it alone.
4. Run full suite after each split. Confirm counts match baseline.

Estimated splits: 10–15 of the 18 Tier 2 files will be split into 2 files
each; the rest stay as-is.

### Wave 8 — Cleanup & Verification

1. Delete any now-empty original files (there shouldn't be any if using
   `git mv` + edit, but verify).
2. Run the full suite one final time.
3. Verify no test was lost: compare total test count against Wave 1 baseline.
4. Update any CI config or documentation that references specific test file
   paths.

## Naming Conventions

When splitting a file, follow these rules:

- **Keep the original name** for the largest or most "core" portion of the
  split. This minimizes churn in developer muscle memory and CI config.
- **Use descriptive suffixes** for the extracted portions:
  `test_ai.py` → `test_ai_endpoints.py`, `test_ai_leakage.py`, etc.
- **Never use generic suffixes** like `test_ai_2.py` or `test_ai_part_b.py`.
  The name must describe the concern.

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
  renaming test methods. No changing assertions. That is a separate concern.
- **Promote fixtures up, never duplicate.** If two new files need the same
  fixture, it goes in `conftest.py`, not in both files.
- **Judgment over formula.** The Tier 2 table says "2 files" but if a file
  doesn't have a clean split point, leave it alone. Forced splits are worse
  than large files.
- **One wave = one commit.** Each wave is independently revertible.

## Risk & Rollback

- **Low risk.** No test logic changes. Splits are class-level cut/paste
  with import adjustments.
- **Fixture breakage** is the main risk. Mitigated by running the full suite
  after every wave and by promoting shared fixtures to `conftest.py` rather
  than duplicating.
- **Rollback.** `git revert <wave-commit>` restores the previous file
  boundaries with no side effects.

## Success Criteria

- [ ] No test file exceeds 500 lines (Tier 1) or remains monolithic with
      unrelated concerns (Tier 2)
- [ ] `pytest tests/` produces identical pass/fail/skip counts to baseline
- [ ] Every new file is runnable in isolation (`pytest tests/<subdir>/<file>`)
- [ ] No duplicated fixtures — shared fixtures live in `conftest.py`
- [ ] File names describe the concern, not arbitrary numbering
- [ ] Total test count matches baseline — no tests lost or duplicated
