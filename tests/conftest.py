"""
Shared pytest fixtures for Chainsmith tests.

Only cross-cutting fixtures that are used by multiple subdirectories
belong here. Domain-specific fixtures live in subdirectory conftest.py files.
"""

import sys
from pathlib import Path

import pytest

# Ensure app is importable
sys.path.insert(0, str(Path(__file__).parent.parent))


# ─── Path Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def project_root() -> Path:
    """Project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def simulations_dir(project_root: Path) -> Path:
    """Simulations YAML directory."""
    return project_root / "app" / "data" / "simulations"


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
