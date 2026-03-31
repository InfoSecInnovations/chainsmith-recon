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
6. Run tests: `pytest tests/`
7. Submit a pull request

## Development Setup

```bash
# Clone and install
git clone https://github.com/infosecinnovations/chainsmith-recon.git
cd chainsmith-recon
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linting
ruff check app/ tests/
ruff format app/ tests/ --check

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

Checks are the core of Chainsmith's reconnaissance capability. To add a new check:

### 1. Choose the Right Base Class

- `BaseCheck`: For checks that operate on the overall context
- `ServiceIteratingCheck`: For checks that run against each discovered service

### 2. Create the Check File

```python
# app/checks/<suite>/my_check.py

from typing import Any
from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.findings import build_finding

class MyCheck(ServiceIteratingCheck):
    """One-line description of what this check does."""
    
    name = "my_check"
    description = "Detailed description of the check"
    
    # When should this check run?
    conditions = [CheckCondition("services", "truthy")]
    
    # What does this check produce for downstream checks?
    produces = ["my_output"]
    
    # What service types does this check apply to?
    service_types = ["http", "api", "ai"]
    
    # Timing
    timeout_seconds = 30.0
    delay_between_targets = 0.2
    
    # Educational metadata
    reason = "Why this check matters for security"
    references = ["OWASP-XXX", "CWE-XXX"]
    techniques = ["technique1", "technique2"]
    
    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        
        # Your check logic here
        
        # Create findings for issues discovered
        result.findings.append(build_finding(
            check_name=self.name,
            title="Issue found",
            description="Details about the issue",
            severity="medium",
            evidence="Supporting evidence",
            host=service.host,
            target=service,
        ))
        
        return result
```

### 3. Register the Check

Add to `app/checks/<suite>/__init__.py`:

```python
from app.checks.<suite>.my_check import MyCheck

__all__ = [..., "MyCheck"]
```

### 4. Add to CLI Registry

Update `app/cli.py` CHECK_REGISTRY:

```python
CHECK_REGISTRY = {
    "<suite>": [
        ...,
        ("my_check", MyCheck),
    ],
}
```

### 5. Write Tests

```python
# tests/checks/test_<suite>.py

class TestMyCheck:
    def test_initialization(self):
        check = MyCheck()
        assert check.name == "my_check"
    
    async def test_check_service(self, sample_service):
        check = MyCheck()
        # Mock HTTP calls
        # Assert expected behavior
```

## Creating Simulations

Simulations allow checks to return predetermined results for training scenarios.

### YAML Structure

```yaml
# app/data/simulations/<suite>/my_simulation.yaml

check_name: my_check
version: "1.0"

behavior:
  failure_mode: none  # none, exception, timeout, malformed
  delay_ms: 50

findings:
  - title: "Simulated finding"
    description: "This is a simulated finding for training"
    severity: medium
    evidence: "Simulated evidence"

outputs:
  my_output:
    - key: value

services:
  - host: simulated.example.com
    port: 8080
    scheme: https
    service_type: api
```

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
