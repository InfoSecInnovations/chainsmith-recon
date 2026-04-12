"""
Tests for CheckLauncher + ObservationWriter integration.

Verifies that observations produced by checks are streamed through
the writer during execution, not just accumulated in memory.
"""

from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import OperationalError

from app.check_launcher import CheckLauncher
from app.checks.base import CheckResult, Observation, Service
from app.db.writers import ObservationWriter

pytestmark = pytest.mark.unit


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class FakeCheck:
    """Minimal check for testing launcher-writer integration."""

    name: str
    conditions: list = field(default_factory=list)
    produces: list = field(default_factory=list)
    _observations: list = field(default_factory=list)
    _outputs: dict = field(default_factory=dict)

    async def run(self, context: dict) -> CheckResult:
        result = CheckResult(success=True)
        result.observations = list(self._observations)
        result.outputs = dict(self._outputs)
        return result

    async def execute(self, context: dict) -> CheckResult:
        return await self.run(context)


def make_observation(
    title: str, severity: str = "medium", host: str = "example.com"
) -> Observation:
    return Observation(
        id=f"obs-{title.lower().replace(' ', '-')}",
        title=title,
        description=f"Description for {title}",
        severity=severity,
        evidence="test evidence",
        target=Service(url=f"https://{host}", host=host, port=443, scheme="https"),
    )


@pytest.fixture
def mock_obs_repo():
    repo = MagicMock()
    repo.bulk_create = AsyncMock(return_value=0)
    return repo


# ═══════════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestLauncherWriterIntegration:
    async def test_observations_streamed_to_writer(self, mock_obs_repo):
        """Observations are written to the writer as checks produce them."""
        check = FakeCheck(
            name="test_check",
            _observations=[
                make_observation("Obs 1"),
                make_observation("Obs 2"),
                make_observation("Obs 3"),
            ],
        )

        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=10)
        launcher = CheckLauncher([check], {}, observation_writer=writer)
        observations = await launcher.run_all()

        # Observations in both memory and writer
        assert len(observations) == 3
        assert writer.count == 3

        # Writer should have flushed (final flush in run_all)
        mock_obs_repo.bulk_create.assert_called_once()

    async def test_writer_flushes_after_each_check(self, mock_obs_repo):
        """Each check completion triggers a flush."""
        check1 = FakeCheck(
            name="check_a",
            _observations=[make_observation("Obs 1")],
            produces=["output_a"],
            _outputs={"output_a": True},
        )
        check2 = FakeCheck(
            name="check_b",
            _observations=[make_observation("Obs 2")],
        )

        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=100)
        launcher = CheckLauncher([check1, check2], {}, observation_writer=writer)
        await launcher.run_all()

        # Exactly 2 flushes: one per check completion (final flush is a no-op on empty buffer)
        assert mock_obs_repo.bulk_create.call_count == 2
        assert writer.count == 2

    async def test_no_writer_still_works(self):
        """Launcher works without a writer (backward compat)."""
        check = FakeCheck(
            name="test_check",
            _observations=[make_observation("Obs 1")],
        )

        launcher = CheckLauncher([check], {})
        observations = await launcher.run_all()

        assert len(observations) == 1

    async def test_writer_db_failure_does_not_halt_scan(self, mock_obs_repo, tmp_path):
        """If the writer's DB fails, the scan still completes."""
        mock_obs_repo.bulk_create.side_effect = OperationalError("DB down", {}, None)

        check = FakeCheck(
            name="test_check",
            _observations=[make_observation("Obs 1"), make_observation("Obs 2")],
        )

        writer = ObservationWriter("scan-1", repo=mock_obs_repo, batch_size=1, scratch_dir=tmp_path)
        launcher = CheckLauncher([check], {}, observation_writer=writer)
        observations = await launcher.run_all()

        # Scan still produces observations in memory
        assert len(observations) == 2
        assert writer.db_failed is True
        # Scratch files exist
        assert (tmp_path / "scan-1" / "observations").exists()
