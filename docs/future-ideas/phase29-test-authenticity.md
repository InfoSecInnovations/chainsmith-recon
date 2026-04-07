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
that requires a real LLM profile. CI skips these; local dev runs
the full suite.

### Implementation

1. Register the marker in `pyproject.toml` (or `pytest.ini`):
   ```toml
   [tool.pytest.ini_options]
   markers = [
       "live_llm: requires a real LLM profile/API key (skipped in CI)",
   ]
   ```

2. Add a CI-side flag to exclude them. In the GitHub Actions workflow:
   ```yaml
   - run: pytest -m "not live_llm"
   ```

3. For local runs with a profile:
   ```bash
   pytest                        # runs everything including live_llm
   pytest --profile=dev          # same, with explicit profile
   pytest -m "not live_llm"     # local run, skip live tests
   ```

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
- Adding real network integration tests (those belong in a separate harness)
