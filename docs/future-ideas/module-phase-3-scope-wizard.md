# Module Phase 3 — Scope Wizard (Interactive Scope Builder)

**Status:** Design / pending implementation
**Module name:** `scope-wizard`
**Tier:** `community`
**Prerequisites:**
- `concurrent-scans-design.md` Phases A–C must land first. Notably, that design **removes `POST /api/v1/scope`**; the wizard's `--apply` behavior changes to POST inline scope to `/api/v1/scan` instead of the old two-step scope-then-scan flow.
- Module System (`module-system-design.md`) must land next.

---

## 1. Goals

An interactive CLI wizard that walks a user through creating a scope configuration via simple linear Q&A, then outputs the result:
1. to stdout (user captures it),
2. to a file (`--out scope.yaml`),
3. directly into core's in-memory scope so the next `chainsmith scan` uses it,
4. or all three in one run (`--out scope.yaml --apply` prints + writes + applies).

- Audience: new users (day-one ergonomics), anyone who wants scope-as-code
- **Create-only** — editing an existing scope is out of scope for v1
- **Simple linear Q&A** — no branching based on target type in v1
- No scenario integration (scenarios are a separate path)

## 2. Non-goals

- Edit-existing support (v2 if requested)
- Smart branching based on target-type detection (adds complexity; users can re-run)
- Compete with **engagement templates** (paid Pro tier) — those are stored, shared, RBAC-gated workspace artifacts. This wizard is a stateless local generator. No shared storage, no versioning, no team-wide reuse.
- Replace `POST /api/v1/scope` — the wizard builds, then applies via that endpoint

---

## 3. Module layout

```
modules/scope-wizard/
├── manifest.toml
├── module.py
├── cli.py                 # `chainsmith scope wizard` command
├── wizard/
│   ├── __init__.py
│   ├── questions.py       # question list + ordering
│   ├── prompts.py         # wraps prompt_toolkit / click.prompt with validation
│   ├── assembler.py       # Q&A answers → ExtendedScopeInput instance
│   └── output.py          # stdout, file (yaml/json), apply-via-API
└── tests/
    ├── test_questions.py  # scripted-input E2E per question path
    └── test_output.py     # formatting + apply
```

### Manifest

```toml
[module]
name = "scope-wizard"
version = "0.1.0"
description = "Interactive CLI wizard for building scope configurations"
tier = "community"
chainsmith_min_version = "1.3.0"

[dependencies]
python = ["prompt_toolkit>=3.0", "pyyaml>=6.0"]

[contributes]
cli_groups = ["scope"]
# Extends the existing 'scope' CLI group with a new 'wizard' subcommand.
# Same CLI-extension requirement as scan-reporter (see §2 of that doc).
```

---

## 4. Question set (v1)

Linear, 8-12 questions. Each maps to a field on `ExtendedScopeInput` (see `app/api_models.py:51`).

| # | Question | Field | Notes |
|---|---|---|---|
| 1 | What's the primary target domain? | `target` | Required. Validated by re-using Pydantic's `ExtendedScopeInput.target` validator. |
| 2 | Additional in-scope hosts/subdomains? (comma-separated, blank to skip) | `allowed_hosts` | Optional |
| 3 | Out-of-scope hosts? | `excluded_hosts` | Optional |
| 4 | Allowed ports? (blank for default 80,443) | `allowed_ports` | Optional |
| 5 | Scan profile? | `profile_name` | Menu: openai / anthropic / ollama / litellm / (leave unset) |
| 6 | Suites to run? | `suites` | Multi-select from core's `AVAILABLE_SUITES` |
| 7 | Any specific checks to include? | `checks` | Multi-select; optional refinement |
| 8 | Any checks to explicitly skip? | `skip_checks` | Optional |
| 9 | Rate limit (requests/sec)? | `rate_limit` | Numeric; default 10 |
| 10 | Scan depth? | `depth` | Menu: shallow / standard / thorough |
| 11 | Require proof-of-scope? | `require_proof` | y/N |
| 12 | Description / notes for this scope? | `description` | Optional free text |

Default-accept: every question has a default; pressing Enter accepts the default. A user can build a working scope in 10 seconds by tapping Enter through everything after question 1.

### Validation

- **Reuse core's Pydantic models directly.** At the end, the assembler builds an `ExtendedScopeInput(**answers)`; Pydantic raises on invalid combinations.
- **Per-question validation** where cheap: target domain format, port numbers in range, rate limit numeric, suite names in `AVAILABLE_SUITES`. On failure, re-prompt with the error message. Don't let the user finish a 2-minute wizard only to fail at the end.
- **Recommended core addition:** `app/scope_validation.py` exposing `validate_scope(dict) -> list[ValidationError]` that wraps Pydantic and adds cross-field rules (e.g., allowed_hosts must include `target`, excluded_hosts mustn't overlap allowed_hosts). This is a basic-feature-sized addition to core, not module territory — the wizard, tests, the scope-endpoint, and future CLI validators all benefit. Until it lands: use Pydantic directly.

---

## 5. Output modes

Flags on `chainsmith scope wizard`:

| Flag | Behavior |
|---|---|
| (none) | Print the resulting YAML to stdout, exit 0 |
| `--out <path>` | Write YAML (or JSON if `.json`) to path; print the path, exit 0 |
| `--apply` | POST to `/api/v1/scope`; print "Scope applied to current session", exit 0 |
| `--out <path> --apply` | Both |
| `--format yaml\|json` | Override format detection from file extension |
| `--dry-run` | Run the Q&A but skip stdout/file/apply — useful for testing the wizard itself |

### Output format

YAML by default (friendlier for humans):

```yaml
# chainsmith scope generated by scope-wizard v0.1.0
# 2026-04-12T14:23:00Z
target: example.com
allowed_hosts:
  - api.example.com
  - staging.example.com
excluded_hosts: []
allowed_ports: [80, 443, 8080]
suites: [web, ai, mcp]
profile_name: anthropic
rate_limit: 10
depth: standard
require_proof: false
description: |
  Q1 pentest scope for example.com
```

The header comment makes it trivially identifiable as wizard output (useful for debug / support).

---

## 6. Prompt library choice

**Chosen:** `prompt_toolkit`.

**Why over alternatives:**
- Click has `prompt`/`confirm` but doesn't do multi-select or auto-complete well.
- `questionary` is nice but adds another dep; prompt_toolkit is already a transitive dep of many tools.
- Rich `Prompt.ask()` works but is string-oriented, weak on multi-select.
- Inquirer is unmaintained.

Prompt_toolkit handles: validation on submit, multi-select, auto-completion (for check names), cross-platform (Win/Mac/Linux via `pyreadline3` on Windows or prompt_toolkit's own impl).

---

## 7. Apply-via-API

After concurrent-scans lands, `POST /api/v1/scope` is gone; scope is inline on `/api/v1/scan`. `--apply` therefore means "apply and start a scan":

1. Build `ExtendedScopeInput` locally.
2. POST to `/api/v1/scan` with the scope inline.
3. On 2xx: print success + returned `scan_id`. Suggest `chainsmith watch --scan <id>`.
4. On error: print the server's validation error (don't just say "failed"), exit 1.
5. If the core API is not reachable, print a helpful message: "Server not reachable at <url>. Run `chainsmith.sh start` first, or drop `--apply` to write YAML only."

Because `--apply` now also starts a scan, consider renaming to `--run` or adding an explicit confirmation prompt — starting a scan is a side effect the old `--apply` didn't have. Open question below.

---

## 8. Testing

- **Scripted-input tests.** `prompt_toolkit` supports scripted-input mode for testing. Each test feeds a canned key sequence and asserts the resulting scope dict.
- **Validation tests.** Feed invalid inputs, assert the wizard re-prompts without crashing.
- **Output tests.** Assert YAML/JSON formatting byte-for-byte against fixtures.
- **Apply test.** Mock the HTTP call; assert the right body goes to `/api/v1/scope`.
- **`--dry-run` test.** Assert no output artifacts are produced.

---

## 9. Open questions

1. **CLI group extension.** Same as scan-reporter — if the module system only allows new top-level groups, command becomes `chainsmith scope-wizard` instead.
2. **Multi-select UX.** prompt_toolkit's built-in checkbox dialog, or a numbered list with toggle-by-index? Dialog is prettier; numbered list is faster for power users. Default to dialog; flag `--simple-prompts` for scripted / CI / SSH-without-alt-screen.
3. **Defaults source.** Should the wizard read existing scope from `/api/v1/scope` and pre-fill defaults from it? (Edge case of edit-existing creeping in — decline in v1 per the non-goals.)
4. **Scope versioning.** When writing to a file, include a `schema_version: 1` field so future wizard versions can read old files?
5. **Autocomplete on check names.** Worth doing, since there are 133+ checks. Core needs to expose `GET /api/v1/checks` (it does). Wizard caches the list on first question and autocompletes from it.
6. **`--apply` semantics change.** With `/api/v1/scope` gone, `--apply` starts a scan as a side effect. Rename to `--run`, add a confirmation prompt, or keep `--apply` and document the behavior change? Leaning toward `--run` for clarity.

---

## 10. Definition of done

- `chainsmith scope wizard` launches the Q&A on Win/Mac/Linux
- All 12 questions flow linearly with sensible defaults (Enter-through works)
- Pydantic validation surfaces clear error messages mid-wizard, not just at the end
- Output modes (stdout, file, apply, combinations) all work
- YAML and JSON output formats both pass golden-file tests
- `--apply` gracefully handles server-not-running
- Scripted-input tests cover happy path + three invalid-input recovery paths
- Manifest validates; removing the module removes the `scope wizard` subcommand
