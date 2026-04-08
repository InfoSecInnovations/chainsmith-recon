# Phase 29 — Test Authenticity Overhaul

Audit performed 2026-04-06. CI passes, but ~40% of test files have
quality issues that undermine confidence in the suite.

---

## Problem Summary

Most security-check tests follow a copy-pasted pattern: hardcode a mock
HTTP response containing the vulnerability indicator, run the check, then
assert the indicator was found. This is circular — it proves plumbing
works, not that detection logic is correct.

---

## Work Items

### 1. Eliminate "testing the mock" pattern in check tests

**Files affected:** `test_agent_discovery.py`, `test_agent_exploitation.py`,
`test_ai_attacks.py`, `test_ai_fingerprint.py`, `test_ai_endpoints.py`,
and ~30 other check test files using `make_response()` / `_mock_client()`.

**What's wrong:** Tests provide the evidence in the mock, then assert it
was detected. The detection/parsing logic is never actually exercised.

**Fix:** Test detection logic directly — call parsing/classification
functions with realistic raw data and verify correct output. Mock only
the network transport, not the analysis.

### 2. Stop mocking the method under test

**Files affected:** `test_network_reverse_dns.py` (`_ptr_lookup`),
`test_network_http_methods.py` (`_probe_service`), `test_llm.py`
(entire HTTP client chain), and similar.

**What's wrong:** `patch.object(check, "_ptr_lookup", ...)` replaces
the function being tested with a fake. The real implementation is
never called.

**Fix:** Mock only external I/O (socket calls, HTTP transport). Let
the real method run against controlled input.

### 3. Add negative / false-positive tests

**What's missing:** Almost no tests verify that benign responses do NOT
trigger findings. A check that flags everything would pass the current
suite.

**Fix:** For every check, add at least one test with a clean/benign
response and assert zero findings.

### 4. Replace overly broad assertions

**Examples:**
- `assert len(findings) >= 1` — should assert specific count, titles,
  severities, evidence strings.
- `assert result.success` — should verify outputs contain expected data.
- `assert result is not None` — meaningless if the function never
  returns None.

**Fix:** Replace with specific assertions on finding title, severity,
evidence content, and count.

### 5. Remove tautological / trivial tests

**Examples:**
- `assert 80 in WEB` — testing that a hardcoded constant contains 80.
- `assert scope.in_scope_domains == []` — testing default matches default.
- `ConcreteCheck(return_value="x")` then `assert result.success` — you
  told it to succeed.

**Fix:** Either delete these or replace with tests that exercise real
edge cases (e.g., what happens with an empty scope? malformed input?).

### 6. Reduce mock setup complexity in test_llm.py

**What's wrong:** 50+ lines of nested `MagicMock` / `AsyncMock` /
`__aenter__` / `__aexit__` wiring to fake an HTTP client, then a
single `assert response.success is True`.

**Fix:** Extract a lightweight fake HTTP client fixture. Or better,
test the LLM response-parsing logic separately from the HTTP layer.

### 7. Create a "detection accuracy" integration test suite

**Purpose:** A small set of end-to-end tests that run real checks
against canned but realistic target responses (served by a local
test fixture), verifying that each check actually detects what it
claims to detect.

**Scope:** Start with 5-10 highest-value checks. Not a replacement
for unit tests — a complement.

### 8. Refactor shared mock helpers

**What's wrong:** `make_response()` and `_mock_client()` are
copy-pasted across 40+ files with slight variations.

**Fix:** Consolidate into a shared `tests/helpers/` module. While
doing so, redesign them to mock transport only (not detection logic).

---

## Suggested Order

1. Item 3 (negative tests) — fastest confidence boost, no refactoring
2. Item 4 (specific assertions) — quick wins, file by file
3. Item 1 + 2 (stop mocking detection logic) — biggest effort, biggest payoff
4. Item 8 (shared helpers) — do alongside item 1
5. Item 5 (remove trivial tests) — cleanup pass
6. Item 6 (LLM test cleanup) — isolated
7. Item 7 (integration suite) — last, builds on all the above

---

## CI Strategy: Marker-Based Test Tiers

Chainsmith requires `--profile` with a real LLM key for certain
operations. Tests that need a live LLM provider must not break CI
(which has no API keys).

**Approach:** Use a `@pytest.mark.live_llm` marker to tag any test
that requires a real LLM profile. Tests auto-skip when no key is
available — no special CI flags needed.

### Implementation

1. Register the marker in `pyproject.toml` (or `pytest.ini`):
   ```toml
   [tool.pytest.ini_options]
   markers = [
       "live_llm: requires a real LLM profile/API key (auto-skipped when unavailable)",
   ]
   ```

2. Add auto-detection in `conftest.py`:
   ```python
   def pytest_collection_modifyitems(config, items):
       if _llm_key_available():
           return  # key present — run everything
       skip_live = pytest.mark.skip(reason="No LLM API key available")
       for item in items:
           if "live_llm" in item.keywords:
               item.add_marker(skip_live)
   ```

3. Usage — `pytest` Just Works everywhere:
   ```bash
   pytest                        # auto-skips live_llm if no key
   pytest --profile=dev          # key available — runs everything
   ```
   CI needs no `-m "not live_llm"` flag; tests auto-skip.

4. Tag any test that calls a real LLM provider:
   ```python
   @pytest.mark.live_llm
   def test_llm_response_parsing_end_to_end():
       ...
   ```

### Which items need the marker?

| Item | Needs `live_llm`? | Reason |
|------|-------------------|--------|
| 1. Stop testing the mock | No | Tests parsing logic with hardcoded realistic data |
| 2. Stop mocking method under test | No | Mocks transport only, no LLM call |
| 3. Negative / false-positive tests | No | Synthetic benign responses |
| 4. Specific assertions | No | Assertion changes only |
| 5. Remove trivial tests | No | Deletions / rewrites |
| 6. LLM test cleanup | Partially | Refactored unit tests: no. Any new end-to-end LLM path test: yes |
| 7. Integration suite | Partially | Local-fixture tests: no. Any variant that hits a real provider: yes |
| 8. Shared helpers | No | Refactoring only |

Most work items are fully CI-safe. The `live_llm` marker is only
needed for tests that deliberately exercise the real provider path.

---

## Out of Scope

- Increasing raw coverage numbers (coverage is already misleadingly high)
- Rewriting the check framework itself
- Modifying check source code (only test files are in scope)
- Adding real network integration tests (those belong in a separate harness)

---

## Audit Inventory (2026-04-08)

Issue key: **1** = Testing the mock · **2** = Mocking the method under test ·
**3** = No negative tests · **4** = Overly broad assertions ·
**5** = Tautological/trivial tests · **6** = Complex mock setup

### Agent / AI Check Tests

| File | Issues | Notes |
|---|---|---|
| test_agent.py | 1, 3, 4, 5 | Mock body contains exact indicator phrases (`"INJECTED - As instructed…"`, `"My system prompt is…"`); `len(endpoints) > 0`; no borderline negative tests; `test_check_metadata` tests constants |
| test_agent_discovery.py | 1, 3, 4 | Mock contains `"delegating to the research agent"` — the exact detection phrase; `>= 1` / `>= 2` bounds; only 404-based negative test |
| test_agent_exploitation.py | 1, 3, 4, 5 | Mock returns `/etc/passwd` content when `"passwd"` in prompt; `result.success`-only assertions; schema-only payload tests |
| test_agent_framework.py | 1, 3, 4 | Mock echoes `CHAINSMITH_RCE_TEST` / `CHAINSMITH_MARKER` canaries; no negative tests for clean responses; `>= 1` assertions |
| test_agent_multiagent.py | 1, 3, 4, 5 | Mock returns `[SYSTEM] Override` marker verbatim; hardcoded count `== 17`; `infer_suite()` tests mapping constants |
| test_ai_attacks.py | 1, 3, 4 | Mock contains literal `"HACKED"` keyword; no borderline-language negative tests |
| test_ai_endpoints.py | 3, 4, 5 | No test for non-AI response on matching path; `_detect_api_format` tests static mapping table; metadata tests tautological |
| test_ai_fingerprint.py | 1, 3, 4 | Mock contains `x-vllm-version` header; `if result.observations:` guard makes assertion conditional; `>= 1` assertions |
| test_ai_leakage.py | 1, 3, 4 | Mock contains `"Traceback (most recent call last):"`, canary string, `/app/models/inference.py`; `if result.observations:` guards |
| test_ai_leakage_disclosure.py | 1, 3, 4 | Mock contains `"You are a helpful assistant…"` matching LEAK_INDICATORS; `if result.observations:` guards |
| test_cag.py | 1, 3, 4, 5 | Mock contains `x-gptcache-hit` header; `result.success`-only assertions on timing/auth tests |
| test_cag_enhanced.py | 3, 4, 5 | Multiple check classes have zero positive detection tests; `len(observations) > 0` with no title/severity; six tautological metadata tests |
| test_cag_security.py | 1, 3, 4, 5 | Mock echoes `CACHE_POISON_MARKER_`; `CacheKeyReverseCheck` etc. have only skip-path tests; hardcoded registry count `== 17` |

### MCP Check Tests

| File | Issues | Notes |
|---|---|---|
| test_mcp.py | 1, 3, 4 | Mock injects `x-mcp-version` header and `capabilities` body; `len(mcp_servers) > 0`; no near-miss negative test |
| test_mcp_controls.py | 1, 3, 4, 5 | Mock contains `"chainsmith-probe\nroot"` verbatim; all severity assertions are bare `> 0`; rate-limit test is structurally predetermined |
| test_mcp_discovery.py | 1, 3, 4 | Mock echoes `protocolVersion` cooperatively; no HTTPS-vs-HTTP negative test; `>= 1` assertions |
| test_mcp_injection.py | 1, 3, 4, 6 | Mock returns `root:x:0:0:root` on `passwd` URI; `"SQL syntax error"` on `OR` URI; complex `mock_client_factory()` for bare severity checks |
| test_mcp_vulnerabilities.py | 1, 3, 4, 5 | Mock returns valid tools list with `auth_required: False`; `len(critical) > 0`; metadata tests are constants |

### Network Check Tests

| File | Issues | Notes |
|---|---|---|
| test_network.py | 2 | `_resolve_host` patched in all run-level tests; real DNS resolution never executes at run level |
| test_network_dns.py | 1, 2, 6 | Mock IP round-trips to assertion; `WildcardDnsCheck._resolve` patched directly; complex `_make_resolve_side_effect` scaffolding |
| test_network_geoip.py | 1, 6 | ASN `16509` injected → `"hosting"` asserted; nested two-reader MagicMock chains |
| test_network_http_methods.py | 2, 3 | `_probe_service` patched in all run tests; no "safe methods only" negative test |
| test_network_service_probe.py | 6 | AsyncHttpClient mock rebuilt identically in ~10 tests; `_classify_service` unit tests are clean |
| test_network_traceroute.py | 2, 4 | `_trace_route` patched; `"traceroute_data" in result.outputs` with no content check |
| test_network_banner_grab.py | 2 | `_grab_banner` patched in run-level tests; `_identify_service` and `_check_redis_auth` tested correctly at unit level |
| test_network_whois.py | 2 | `_domain_whois` and `_asn_lookup` patched; parsing methods tested correctly at unit level |
| test_network_ipv6.py | 2 | `_resolve_aaaa` patched in run tests; `_sync_resolve_aaaa` tested directly |
| test_network_tls.py | 2, 5 | `_get_cert_info` and `_probe_protocols` patched; tautological `result.success` after full mock-out |
| test_network_reverse_dns.py | 2 | `_ptr_lookup` patched; socket-fallback tests exercise real code |
| test_port_profiles.py | 5 | `assert 80 in WEB`, `assert DEFAULT_PROFILE == "lab"` — tests constants equal themselves |

### Web Check Tests

| File | Issues | Notes |
|---|---|---|
| test_web.py | 1, 3, 4 | Mock body contains `/api/internal/`, `/.git/`; no benign-robots.txt negative test; `len(observations) > 0` |
| test_web_api.py | 1, 3, 4 | Mock contains literal `"Swagger UI"` in HTML; no non-OpenAPI rejection test |
| test_web_error_page.py | 1, 4, 5 | Mock contains exact framework signatures (`DEBUG = True`, `Werkzeug Debugger`); `result.success`-only assertions |
| test_web_favicon.py | 2, 4, 5 | `_check_alpn` patched via `patch.object`; `result.success`-only error handling |
| test_web_header_grading.py | 3 | Minor: no test for completely absent `Permissions-Policy` header |
| test_web_hsts_sri.py | 3, 4 | No preloaded-but-missing-`includeSubDomains` test; `any(...)` without severity check |
| test_web_redirect.py | 1, 4 | Mock performs the 302 redirect to `evil.example.com`; `>= 1` assertion |
| test_web_security_exposure.py | 1, 2, 4 | Mock contains `[core]\nrepositoryformatversion = 0`; `_is_intrusive_allowed` patched; `any(severity == "critical")` |
| test_web_sitemap.py | 4 | `any("sitemap-discovered" in ...)` without URL count or path check |
| test_web_ssrf.py | 1, 4 | Mock returns SSRF-indicator text `"url parameter is required"`; `isinstance(..., list)` only |
| test_web_mass_assignment.py | 1, 2, 4 | Mock reflects `{"is_admin": True}` back; `_gather_endpoints` patched; `>= 1` |
| test_web_default_debug.py | 1, 2, 4, 5 | Mock contains exact debug signatures; `_is_intrusive_allowed` patched; `>= 1` with substring only |
| test_web_security_detection.py | 1, 2, 3, 4 | Mock contains exact WAF fingerprint headers; no partial-header false-positive test |

### RAG Check Tests

| File | Issues | Notes |
|---|---|---|
| test_rag.py | 1, 4, 5 | Mock returns Chroma API shape / `pinecone-api-version` header; `result.success`-only assertions |
| test_rag_retrieval.py | 1, 4, 5 | Mock contains `"DB password: secretpass123"`; conditional `if` guards on assertions; dead assertion |
| test_rag_storage.py | 1, 4, 5 | Mock returns full Chroma collections response; `if result.outputs.get(...)` guards; dead assertion |
| test_rag_injection.py | 1, 4, 5 | Mock returns `x-cache: HIT`; `result.success`-only assertions |
| test_rag_injection_vectors.py | 1, 2, 4, 5 | Mock returns `CHUNK_BOUNDARY_BYPASSED` canary; `conditions[0].output_name` attribute reads; hardcoded `== 17` |

### Core Tests

| File | Issues | Notes |
|---|---|---|
| test_chain.py | 3, 4 | `len(SUITE_ORDER) >= 7`; conditional assertion in parallel flag test |
| test_check_runner.py | 3 | No negative tests for malformed check registration |
| test_check_runner_findings.py | 3 | No negative tests for malformed observation objects |
| test_config.py | 5 | Default-value tests verify constants equal their own literals |
| test_adjudicator.py | 3, 5 | No test for unparseable LLM severity; tests hardcoded class defaults |
| test_writers.py | — | Clean |
| test_launcher_writer_integration.py | 4 | `bulk_create.call_count >= 2` without verifying flush points |
| test_on_critical.py | 2 | `_resolve_on_critical` patched in every launcher behavior test |
| test_base_check.py | 5 | Enum value tests verify string constants |
| test_base_check_execution.py | — | Clean |

### CLI Tests

| File | Issues | Notes |
|---|---|---|
| test_cli.py | 4, 5, 6 | `exit_code == 0` only; hardcoded version `"1.3.0"`; complex MagicMock client setup |
| test_cli_profiles.py | 4 | `exit_code == 0` without output inspection |
| test_preferences.py | 5 | Default-compared-to-default tests |
| test_preferences_api.py | 3, 6 | No invalid-value tests; complex `sys.modules` purge fixture |

### DB Tests

| File | Issues | Notes |
|---|---|---|
| test_db.py | 4, 5 | Schema check only verifies no error; default config tests constants |
| test_profile_store.py | 4 | `assert result is True` without inspecting written content |
| test_finding_overrides.py | — | Clean |
| test_db_orchestrator.py | 4 | Error test only checks return is `None` |
| test_db_repositories.py | — | Clean |
| test_engagements.py | — | Clean |
| test_engagements_tracking.py | 4 | `new + regressed >= 1` — combined overly broad assertion |

### LLM Tests

| File | Issues | Notes |
|---|---|---|
| test_llm.py | 5, 6 | Enum constant tests; 50+ lines of nested `AsyncMock` `__aenter__`/`__aexit__` wiring |
| test_payloads.py | 4 | `len(all_payloads) >= 40`; `len(payloads) > 10` — overly broad counts |

### Report Tests

| File | Issues | Notes |
|---|---|---|
| test_reports_ui.py | 4 | `or` disjunction assertions; `result["content"]` truthy-only check |
| test_report_delta.py | — | Clean |
| test_report_trend.py | — | Clean |
| test_viz_coverage.py | 5 | Static HTML/JS/CSS string-presence checks |
| test_viz_heatmap.py | 5 | Static HTML/JS/CSS string-presence checks |
| test_viz_radar.py | 5 | Static HTML/JS/CSS string-presence checks |
| test_viz_timeline.py | 5 | Static HTML/JS/CSS string-presence checks |
| test_report_compliance.py | — | Clean |
| test_report_executive.py | — | Clean |
| test_report_technical.py | 4 | `len(content) > 1000` without PDF structure/magic byte check |
| test_reports_targeted.py | — | Clean |
| test_reports_phase8b.py | 5 | Entire file is static template string-presence assertions |
| test_reports_sarif.py | — | Clean |

### Scanning Tests

| File | Issues | Notes |
|---|---|---|
| test_proof_of_scope.py | 5 | Enum value tests verify string constants |
| test_proof_of_scope_ops.py | — | Clean |
| test_scan_advisor.py | 3, 5 | Default config constant tests; no malformed-metadata negative tests |
| test_scenarios.py | — | Clean |
| test_scenario_manager.py | 4, 5 | `len(available) > 0`; conditional fallback masks auto-load path |
| test_simulated_check.py | — | Clean |
| test_simulated_check_host.py | 4 | `len(checks) > 0` |
| test_scans_api.py | 4 | `"T" in timestamp` instead of full ISO 8601 validation |

### Trend Tests

| File | Issues | Notes |
|---|---|---|
| test_trend.py | — | Clean |
| test_trend_engagement.py | — | Clean |

---

## Audit Summary

**Total files audited:** 82
**Files with issues:** 67 (82%)
**Clean files:** 15 (18%)

### Issue prevalence

| Issue | Count | Most affected areas |
|-------|-------|---------------------|
| 1. Testing the mock | 33 files | Check tests (agent, AI, CAG, MCP, web, RAG) |
| 2. Mocking method under test | 16 files | Network checks, web checks, core |
| 3. No negative tests | 18 files | Check tests, core |
| 4. Overly broad assertions | 38 files | Everywhere |
| 5. Tautological/trivial tests | 28 files | Metadata tests, viz tests, enum tests |
| 6. Complex mock setup | 6 files | LLM, MCP injection, network DNS/geoip, CLI |

### Highest-severity files (3+ issues)

- test_agent.py (1, 3, 4, 5)
- test_agent_exploitation.py (1, 3, 4, 5)
- test_agent_multiagent.py (1, 3, 4, 5)
- test_cag.py (1, 3, 4, 5)
- test_cag_security.py (1, 3, 4, 5)
- test_mcp_controls.py (1, 3, 4, 5)
- test_mcp_injection.py (1, 3, 4, 6)
- test_mcp_vulnerabilities.py (1, 3, 4, 5)
- test_web_default_debug.py (1, 2, 4, 5)
- test_web_security_detection.py (1, 2, 3, 4)
- test_web_security_exposure.py (1, 2, 4)
- test_web_mass_assignment.py (1, 2, 4)
- test_rag_injection_vectors.py (1, 2, 4, 5)
- test_cli.py (4, 5, 6)
- test_network_dns.py (1, 2, 6)
