# Phase 43: Check Subdirectory Restructure

> **STATUS: SUPERSEDED by [`phase56-component-modularization.md`](phase56-component-modularization.md).**
> The subdirectory restructure has been merged with `phase17-check-configurability.txt`
> and the component-shape portion of `module-system-design.md` into a single
> coordinated rollout. The 7-suite migration plan here maps directly onto
> phase 56 sub-phases 56.2-56.8. Filenames now follow the folder-name-prefix
> rule (e.g. `ports.py` + `ports.contract.yaml` + `ports.config.yaml`) rather
> than generic `check.py` + `config.yaml`, for conversational and IDE clarity.
> Retained here as historical reference only.

## Overview

Restructure every check from a flat file (`app/checks/web/robots.py`)
into a self-contained subdirectory (`app/checks/web/robots/`) containing
the check script, a config YAML, and the test file. Add an auto-discovery
loader that replaces the hand-maintained import list in `check_resolver.py`.

The result: checks become fully modular, user-configurable components
that can be added, removed, or distributed independently.

## Motivation

1. **`get_real_checks()` is a 300-line manual import list.** Adding a
   check means editing `check_resolver.py`, adding imports, and
   placing the instance at the correct position. This is error-prone
   and doesn't scale.

2. **Check metadata is scattered.** Dependencies, phase, suite
   membership, timeouts, and educational metadata are all hardcoded
   as class attributes. There's no single place a user can look at or
   edit to understand and tune a check.

3. **Suite inference is fragile.** `infer_suite()` uses string-pattern
   matching against check names. A config YAML with an explicit `suite`
   field eliminates this entirely.

4. **Tests are disconnected.** `tests/checks/test_web.py` has no
   structural relationship to `app/checks/web/headers.py`. Co-locating
   test files makes it obvious when a check is untested.

5. **Swarm readiness.** Distributed check execution (in development)
   benefits from checks that are self-describing, independently
   loadable units.

## Target Directory Structure

```
app/checks/
  web/
    __init__.py              # Suite-level config, auto-generated exports
    suite.yaml               # Suite-level defaults (optional)
    robots/
      __init__.py            # Exports RobotsTxtCheck
      check.py               # RobotsTxtCheck class
      config.yaml            # Metadata, defaults, dependencies
      test_robots.py         # Tests for this check
    headers/
      __init__.py
      check.py
      config.yaml
      test_headers.py
    ...
  network/
    suite.yaml
    dns_enumeration/
      __init__.py
      check.py
      config.yaml
      test_dns_enumeration.py
    ...
```

## Config YAML Schema

Each check's `config.yaml` is the single source of truth for metadata
that was previously hardcoded in class attributes. The check class
still owns runtime logic; the YAML owns identity and tunables.

```yaml
# app/checks/web/robots/config.yaml

name: robots_txt
description: "Retrieve robots.txt and identify potentially sensitive paths"
suite: web
enabled: true

# Execution
phase: 3                          # Replaces positional ordering in get_real_checks()
depends_on:                       # Replaces CheckCondition declarations
  - output: services
    operator: truthy
produces:
  - robots_paths
service_types: [http, html, api]

# Tunables (user-adjustable defaults)
defaults:
  timeout_seconds: 30.0
  delay_between_targets: 0.2
  requests_per_second: 10.0
  intrusive: false

# Educational
educational:
  reason: "robots.txt often reveals hidden paths admins want to keep from search engines"
  references:
    - "OWASP WSTG-INFO-03"
    - "RFC 9309"
  techniques:
    - "passive reconnaissance"
    - "path discovery"

# Check-specific tunable parameters
parameters:
  interesting_patterns:
    - admin
    - internal
    - api
    - debug
    - config
    - backup
    - private
    - secret
    - model
    - ml
    - ai
```

## Suite-Level Config (Optional)

Suites can define shared defaults that individual checks inherit from.

```yaml
# app/checks/web/suite.yaml

suite: web
defaults:
  timeout_seconds: 30.0
  delay_between_targets: 0.2
  requests_per_second: 10.0
  service_types: [http, html, api]
```

Individual check configs override suite defaults. User overrides
(a future user-level config file) override both.

## Auto-Discovery Loader

Replace `get_real_checks()` with a filesystem walker.

```python
# app/check_loader.py  (new file, replaces bulk of check_resolver.py)

def discover_checks(suites: list[str] | None = None) -> list[BaseCheck]:
    """
    Walk app/checks/{suite}/{check_name}/ directories.
    For each subdirectory containing check.py + config.yaml:
      1. Load config.yaml
      2. Skip if enabled: false
      3. Import check.py, find the BaseCheck subclass
      4. Instantiate, apply config overrides
      5. Collect into phase-ordered list
    """
```

Key behaviors:
- **Phase ordering:** Sort discovered checks by `(suite_order, phase)`
  to preserve the current execution dependency chain.
- **Validation:** Fail loud on missing required fields (name, suite,
  phase) at startup, not at scan time.
- **Config merge:** `suite.yaml` defaults < `config.yaml` defaults <
  user overrides (future).
- **Backward compat with custom checks:** The existing
  `app/checks/custom/` registry pattern still works. Custom checks
  can adopt the subdirectory format or keep using the registry.

## Changes to BaseCheck

The class attributes that move into config.yaml become optional
(defaulted) on the class and get overridden at instantiation:

```python
class BaseCheck(ABC):
    # These become "set by loader from config.yaml"
    name: str = "unnamed_check"
    description: str = ""
    # conditions built from config.yaml depends_on
    # produces, service_types, timeout, etc. — all settable

    @classmethod
    def from_config(cls, config: dict) -> "BaseCheck":
        """Instantiate and apply config.yaml overrides."""
        instance = cls()
        instance.name = config["name"]
        instance.description = config.get("description", instance.description)
        instance.timeout_seconds = config["defaults"].get(
            "timeout_seconds", instance.timeout_seconds
        )
        # ... etc
        return instance
```

Check classes remain the authority on `run()` / `check_service()`
logic. The YAML just configures the knobs.

## Changes to check_resolver.py

`check_resolver.py` shrinks dramatically:

- `get_real_checks()` becomes a one-liner call to the loader.
- `infer_suite()` is deleted — suite comes from config.yaml.
- `filter_by_suites()` uses the explicit suite field.
- `apply_scenario()` and `filter_by_techniques()` stay as-is.

## Test Co-location

### pytest Discovery

Add to `pyproject.toml` or `pytest.ini`:

```ini
[tool:pytest]
testpaths = tests app/checks
python_files = test_*.py
```

This lets pytest discover tests in both the traditional `tests/`
directory and the new co-located locations.

### Migration Strategy

Tests move alongside their checks:
- `tests/checks/test_web.py` -> `app/checks/web/headers/test_headers.py`
  (split per-check if the test file covers multiple checks)
- `tests/checks/test_network_dns.py` -> `app/checks/network/dns_enumeration/test_dns_enumeration.py`

Tests that span multiple checks or test the runner/framework stay in
`tests/checks/` or `tests/core/`.

## Implementation Plan

### Step 1: Config Schema and Loader

Create the auto-discovery loader (`app/check_loader.py`) and define
the config.yaml schema. Write a schema validator. Test the loader
against a mock directory structure with a few synthetic checks.

**Validates:** The loader correctly discovers, orders, and
instantiates checks from subdirectories.

### Step 2: Pilot Migration — Web Suite

Convert the `web/` suite (23 checks) to subdirectory format:
- Create subdirectories for each check
- Move check scripts to `check.py`
- Extract metadata into `config.yaml`
- Move corresponding tests from `tests/checks/`
- Create `web/suite.yaml`
- Update `web/__init__.py` to auto-export from subdirectories

Run full test suite — all web check tests must pass identically.

### Step 3: Migrate Remaining Suites

Convert remaining suites one at a time, verifying tests after each:
- `network/` (13 checks)
- `ai/` (18 checks)
- `mcp/` (18 checks)
- `agent/` (16 checks)
- `rag/` (17 checks)
- `cag/` (17 checks)

### Step 4: Wire Loader into check_resolver.py

Replace `get_real_checks()` with a call to the new loader. Delete
`infer_suite()`. Verify all filtering paths still work (techniques,
check_names, suites). Run full integration tests.

### Step 5: BaseCheck.from_config() and User Overrides

Add `from_config()` to BaseCheck. Allow check classes to declare
which `parameters` from the config they accept (e.g.,
`INTERESTING_PATTERNS` in robots). Wire this into the loader so
config.yaml parameters flow into the check instance.

This step also lays the groundwork for a user-level override file
(e.g., `~/.chainsmith/check_overrides.yaml`) — but that file itself
is a future phase.

### Step 6: Cleanup

- Delete dead imports from `check_resolver.py`
- Remove `infer_suite()` and its pattern tables
- Update suite `__init__.py` files for auto-export
- Update any docs referencing the old structure
- Verify `_get_custom_checks()` still works for non-migrated custom
  checks

## Open Questions

1. **Should check.py keep declaring class attributes as defaults, or
   should config.yaml be the sole source?** Leaning toward: class
   attributes remain as code-level defaults, config.yaml overrides
   them. This means a check works even without a config.yaml (just
   with hardcoded defaults), which is useful for development.

2. **How granular should user overrides get?** Per-check? Per-suite?
   Global? Probably all three with a merge order:
   `global < suite < check < user-per-check`. But that's a future
   phase concern.

3. **Should simulated checks (scenarios) adopt the same structure?**
   Probably yes for consistency, but scenario simulations live in
   `scenarios/`, not `app/checks/`. Defer to a future phase.

4. **Does the `custom/` registry pattern survive or get replaced?**
   Keep both: custom checks can use subdirectory format (preferred)
   or the legacy registry. Remove the registry only when all custom
   checks have migrated.

5. **Phase numbering vs. dependency graph.** Numeric phases are
   simple but can't express "run after X OR Y." If we need OR
   dependencies later, switch to a DAG with `depends_on` check
   names. For now, phases + `depends_on` outputs are sufficient.

## Risk

- **Regressions during migration.** Mitigated by migrating one suite
  at a time with full test runs after each.
- **Test discovery confusion.** Two test locations (co-located +
  `tests/`) could cause pytest to run the same test twice if
  configured wrong. Mitigated by removing the old test file after
  moving it.
- **Import path changes.** Any code doing
  `from app.checks.web.robots import RobotsTxtCheck` breaks when
  `robots.py` becomes `robots/check.py`. Mitigated by the
  `robots/__init__.py` re-export. Existing import paths stay valid.
