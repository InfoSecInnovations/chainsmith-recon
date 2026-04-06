"""Fixtures for scanning tests."""

from pathlib import Path

import pytest


@pytest.fixture
def scenarios_dir(project_root: Path) -> Path:
    """Scenarios directory."""
    return project_root / "scenarios"
