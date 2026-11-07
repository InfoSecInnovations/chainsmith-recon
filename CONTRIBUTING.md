# Contributing to Chainsmith Recon

Thank you for your interest in contributing to Chainsmith Recon! This document provides guidelines and information for contributors.

## Code of Conduct

Be respectful, inclusive, and constructive. We're all here to build better security tools together.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/chainsmith-recon.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Install dev dependencies: `pip install -e ".[dev]"`
5. Make your changes
6. Run tests: `pytest` (covers `tests/` and the co-located check tests)
7. Submit a pull request

## Development Setup

```bash
# Clone and install
git clone https://github.com/infosecinnovations/chainsmith-recon.git
cd chainsmith-recon
pip install -e ".[dev]"

# Run tests (tests/ plus co-located component tests)
pytest

# Run linting
ruff check app/ tests/
ruff format app/ tests/ --check

# Validate every component contract
chainsmith dev verify-contracts

# Type checking
mypy app/
```

## Pull Request Process

1. Update documentation if adding new features
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md with your changes
5. Request review from maintainers

## Adding New Checks

Checks are the core of Chainsmith's reconnaissance capability. Each check is a
self-contained folder that the loader discovers automatically — there is no
registry to edit.

### 1. Scaffold the Folder

```bash
chainsmith dev new-check --suite web --name web_my_check --description "One-line description"
```

This creates:

```
app/checks/web/web_my_check/
├── __init__.py          # re-exports the entry class
├── check.py             # the check implementation
├── contract.yaml        # identity + I/O contract (the loader reads this)
├── config.yaml          # tunables: enabled, on_critical, timeouts, rate limits
└── tests/
    └── test_web_my_check.py
```

Conventions:

- Name the check with its suite prefix (`web_`, `network_`, `ai_`, `mcp_`, `agent_`, `rag_`, `cag_`). The folder name and the `name` in `contract.yaml` must match.
- Names must not contain `__`.
- Organization-specific checks go in `app/checks/custom/` (`--suite custom`, named `custom_<name>`). Upstream updates never touch that directory.

`chainsmith dev` commands are hidden from `--help` and must be run from the repository root.

### 2. Fill In the Contract

`contract.yaml` is the source of truth for what the check is and how it connects
to other checks:

```yaml
id: 3f0c...                     # generated UUID — leave as is
name: web_my_check
type: check
description: "One-line description"
entry: check.py:MyCheck

suite: web
depends_on:                     # context keys that must exist before this runs
  - output_name: services
    operator: truthy
produces: [my_output]           # context keys this check adds for downstream checks

intrusive: false                # true for injection, writes, auth attempts
service_types: [http, html, api]
parallel_safe: false

outputs:
  observations: [Observation]
side_effects: [network]
techniques: [fingerprinting]
references: [OWASP WSTG-INFO-02, CWE-200]
reason: "Why a pentester would run this"

severity:                       # required for built-in checks (the scaffold omits it)
  model: fixed
  default: low
  observations:                 # one entry per discriminator the grader emits
    my-issue: medium
```

`severity.model` is either `fixed` (a severity per observation type, listed under
`observations`) or `contextual` (a `default` plus a `range` such as
`[info, critical]`, with the grader deciding within it). Keep `conditions`,
`produces`, and `service_types` in `check.py` consistent with the contract.

### 3. Write the Probe and the Grade

Every built-in check is split in two:

- **Probe** (`check_service()` for a `ServiceIteratingCheck`, or `run()` for a `BaseCheck`) — send the stimulus, attach the exchange to a **candidate**, and judge nothing.
- **Grade** (`grade()`) — re-read the recorded evidence and return one `Verdict` per judgement. It never touches the network.

```python
# app/checks/web/web_my_check/check.py

from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig


class MyCheck(ServiceIteratingCheck):
    """One-line description of what this check does."""

    name = "web_my_check"
    description = "One-line description"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["my_output"]
    service_types = ["http", "html", "api"]

    # ── Probe: send, record, assert nothing ─────────────────────
    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        async with AsyncHttpClient(HttpConfig(timeout_seconds=10.0)) as client:
            resp = await client.get(service.url)
        if resp.error:
            result.errors.append(f"{service.url}: {resp.error}")
            return result

        candidate = self.create_candidate(host=service.host, target=service)
        candidate.attach(
            exchange_from_response(
                resp,
                check_name=self.name,
                scan_id=context.get("scan_id") or "",
                host=service.host,
            )
        )
        result.candidates.append(candidate)
        return result

    # ── Grade: read the recorded response, place severity ───────
    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        exchange = next(iter(evidence.completed()), None)
        if exchange is None:
            return []
        headers = {k.lower() for k in (exchange.response_headers or {})}
        if "x-debug" not in headers:
            return []
        return [
            Verdict(
                severity="medium",
                confidence=0.9,
                discriminator="my-issue",
                title="Debug header exposed",
                description="The response carries an X-Debug header.",
                evidence="X-Debug header present",
                reasoning="Header present in the recorded response",
                evidence_ids=[exchange.id],
            )
        ]
```

Do not build observations in the probe (`create_observation`, `Observation(...)`):
the grading stage is the only place observations are created.
`tests/checks/test_probe_grade_coverage.py` fails any built-in check that has no
`grade()` or emits observations directly. See
`app/checks/web/web_header_analysis/check.py` for a complete example.

### 4. Tune `config.yaml`

```yaml
enabled: true
on_critical: annotate          # annotate | skip_downstream | stop

defaults:
  timeout_seconds: 30
  requests_per_second: 10
  retry_count: 1
  delay_between_targets: 0.1
```

### 5. Write Tests

Tests live next to the check in its `tests/` folder and are collected
automatically (`testpaths` in `pyproject.toml` includes `app/checks`). Test the
probe with mocked HTTP (`respx`), and test `grade()` directly by handing it
recorded evidence — no network needed.

### 6. Verify

```bash
chainsmith dev verify-contracts                  # contract schema, folder/name match, severity rules
chainsmith dev show-config --check web_my_check  # resolved config and where each value came from
pytest app/checks/web/web_my_check
```

Discovery refuses to load checks if any contract fails verification, so run
`verify-contracts` before committing.

### Re-grading a Captured Scan

When you change a grader, you can replay it against a scan recorded with
`--capture` without re-sending any traffic:

```bash
chainsmith dev regrade <scan_id> --check web_my_check           # show what would change
chainsmith dev regrade <scan_id> --check web_my_check --apply   # write it back
```

## Creating Simulations

Simulations let a scenario replace a real check with predetermined results, for
training or for targets that can't withstand a particular test. They live in
`scenarios/<name>/simulations/<suite>/` (scenario-specific) or
`app/checks/simulator/simulations/<suite>/` (shared), and are listed in the
scenario's `scenario.json`.

```yaml
# scenarios/my-scenario/simulations/web/web_my_check_my_scenario.yaml

suite: web
emulates: web_my_check          # must match the current check name exactly
target: "www.my-scenario.local"
disposition: issue_found

behavior:
  latency_ms: 50
  failure_mode: none            # none | exception | timeout | malformed

output:
  my_output:
    - key: value

findings:
  - title: "Simulated finding"
    description: "This is a simulated observation for training"
    severity: medium
    evidence: "Simulated evidence"
```

See [docs/scenarios/creating.md](docs/scenarios/creating.md) for the full field reference.

## Code Style

- Use `ruff` for linting and formatting
- Follow PEP 8 conventions
- Use type hints for function signatures
- Write docstrings for public functions and classes
- Keep lines under 100 characters

## Commit Messages

Use conventional commit format:

```
type(scope): description

feat(checks): add MCP endpoint discovery check
fix(cli): handle missing scenario gracefully
docs(readme): add configuration section
test(ai): add prompt leakage tests
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

## Testing Guidelines

- Write tests for all new functionality
- Use pytest fixtures for common setup
- Mock external HTTP calls with `respx` or `unittest.mock`
- Aim for >80% coverage on new code
- Test both success and error paths

## Documentation

- Update README.md for user-facing changes
- Add docstrings to new classes and functions
- Include examples in docstrings where helpful
- Update CHANGELOG.md for all notable changes

## Questions?

Open an issue for questions or discussion. We're happy to help!
