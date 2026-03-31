"""
Shared pytest fixtures for Chainsmith tests.
"""

import sys
from pathlib import Path
from typing import Any

import pytest

# Ensure app is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.checks.base import BaseCheck, CheckResult, Finding, Service


# ─── Path Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def project_root() -> Path:
    """Project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def simulations_dir(project_root: Path) -> Path:
    """Simulations YAML directory."""
    return project_root / "app" / "data" / "simulations"


@pytest.fixture
def scenarios_dir(project_root: Path) -> Path:
    """Scenarios directory."""
    return project_root / "scenarios"


@pytest.fixture
def temp_data_dir(tmp_path: Path) -> Path:
    """Temporary data directory for file-based tests."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir


# ─── Service Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def sample_service() -> Service:
    """Basic HTTP service."""
    return Service(
        url="http://test.local:8080",
        host="test.local",
        port=8080,
        scheme="http",
        service_type="http",
        metadata={"discovered_by": "test"},
    )


@pytest.fixture
def sample_ai_service() -> Service:
    """AI service for AI check tests."""
    return Service(
        url="http://ai.test.local:8000",
        host="ai.test.local",
        port=8000,
        scheme="http",
        service_type="ai",
        metadata={"framework": "vllm"},
    )


@pytest.fixture
def sample_services(sample_service: Service, sample_ai_service: Service) -> list[Service]:
    """Multiple services for iteration tests."""
    return [sample_service, sample_ai_service]


# ─── Context Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def empty_context() -> dict[str, Any]:
    """Empty check context."""
    return {}


@pytest.fixture
def basic_context(sample_services: list[Service]) -> dict[str, Any]:
    """Context with services populated."""
    return {
        "services": sample_services,
        "target": "test.local",
    }


# ─── Finding Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def sample_finding(sample_service: Service) -> Finding:
    """Sample finding for testing."""
    return Finding(
        id="F-001",
        title="Test Finding",
        description="A test finding for unit tests",
        severity="medium",
        evidence="Sample evidence text",
        target=sample_service,
        target_url=sample_service.url,
        check_name="test_check",
        references=["https://example.com/ref"],
    )


# ─── Environment Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def clean_env(monkeypatch):
    """Remove Chainsmith-related environment variables."""
    env_vars = [
        "CHAINSMITH_CONFIG",
        "CHAINSMITH_TARGET_DOMAIN",
        "CHAINSMITH_SCENARIO",
        "CHAINSMITH_IN_SCOPE_DOMAINS",
        "CHAINSMITH_OUT_OF_SCOPE_DOMAINS",
        "LITELLM_BASE_URL",
        "LITELLM_MODEL_CHAINSMITH",
        "DATA_DIR",
    ]
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def temp_config_file(tmp_path: Path) -> Path:
    """Temporary YAML config file."""
    config_file = tmp_path / "chainsmith.yaml"
    config_file.write_text(
        """
target_domain: test.example.com
scope:
  in_scope_domains:
    - test.example.com
    - "*.test.example.com"
  out_of_scope_domains:
    - admin.test.example.com
  in_scope_ports: [80, 443, 8080]
litellm:
  base_url: http://localhost:4000/v1
  model_chainsmith: test-model
"""
    )
    return config_file


# ─── Dummy Check for Testing ──────────────────────────────────────────────────


class DummyCheck(BaseCheck):
    """Minimal check implementation for testing BaseCheck behavior."""

    name = "dummy_check"
    description = "A dummy check for testing"
    produces = ["dummy_output"]

    def __init__(self, should_fail: bool = False, output_value: Any = "dummy"):
        super().__init__()
        self.should_fail = should_fail
        self.output_value = output_value
        self.run_called = False

    async def run(self, context: dict[str, Any]) -> CheckResult:
        self.run_called = True

        if self.should_fail:
            raise RuntimeError("Intentional test failure")

        return CheckResult(success=True, outputs={"dummy_output": self.output_value})


@pytest.fixture
def dummy_check() -> DummyCheck:
    """Dummy check instance."""
    return DummyCheck()


@pytest.fixture
def failing_check() -> DummyCheck:
    """Check that always raises an exception."""
    return DummyCheck(should_fail=True)
