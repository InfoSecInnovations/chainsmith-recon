"""
ObservationWriter: an id collision is a check bug, not a database outage.

A check that mints the same observation id twice used to flip the writer into
its scratch-space fallback for the rest of the scan, so every later check's
observations silently left the database. Only the colliding row may leave it.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError

from app.db.writers import ObservationWriter

pytestmark = pytest.mark.unit


def _obs(name: str) -> dict:
    return {"id": f"obs-{name}", "title": name, "severity": "low", "check_name": "dup_check"}


def _unique_ids_repo(stored: set[str]) -> MagicMock:
    """A repository whose primary key is enforced the way the database enforces it."""

    async def bulk_create(scan_id, observations):
        ids = [o["id"] for o in observations]
        if len(set(ids)) != len(ids) or stored & set(ids):
            raise IntegrityError(
                "INSERT", {}, Exception("UNIQUE constraint failed: observations.id")
            )
        stored.update(ids)
        return len(ids)

    repo = MagicMock()
    repo.bulk_create = AsyncMock(side_effect=bulk_create)
    return repo


def _scratch_ids(tmp_path) -> list[str]:
    files = sorted((tmp_path / "scan-1" / "observations").glob("*.json"))
    return [json.loads(f.read_text())["id"] for f in files]


async def test_a_collision_keeps_the_database_for_everything_else(tmp_path):
    stored: set[str] = set()
    writer = ObservationWriter(
        "scan-1", repo=_unique_ids_repo(stored), batch_size=3, scratch_dir=tmp_path
    )

    await writer.write(_obs("a"))
    await writer.write(_obs("a"))  # the same id twice in one batch
    await writer.write(_obs("b"))  # batch flushes and collides
    await writer.write(_obs("c"))  # a later check, which used to go to scratch
    await writer.flush()

    assert writer.db_failed is False
    assert writer.collisions == 1
    assert writer.count == 4
    assert stored == {"obs-a", "obs-b", "obs-c"}
    assert _scratch_ids(tmp_path) == ["obs-a"]


async def test_a_collision_with_an_earlier_batch(tmp_path):
    stored: set[str] = set()
    writer = ObservationWriter(
        "scan-1", repo=_unique_ids_repo(stored), batch_size=1, scratch_dir=tmp_path
    )

    await writer.write(_obs("a"))
    await writer.write(_obs("a"))
    await writer.write(_obs("b"))

    assert writer.db_failed is False
    assert writer.collisions == 1
    assert stored == {"obs-a", "obs-b"}


async def test_an_outage_during_the_row_retry_still_falls_back(tmp_path):
    calls = {"n": 0}

    async def bulk_create(scan_id, observations):
        calls["n"] += 1
        if calls["n"] == 1:
            raise IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed"))
        if calls["n"] == 2:
            return 1
        raise OperationalError("database is locked", {}, None)

    repo = MagicMock()
    repo.bulk_create = AsyncMock(side_effect=bulk_create)
    writer = ObservationWriter("scan-1", repo=repo, batch_size=3, scratch_dir=tmp_path)

    for name in ("a", "b", "c"):
        await writer.write(_obs(name))

    assert writer.db_failed is True
    assert writer.collisions == 0
    # "a" landed on its own retry; the outage sent the unwritten rest to scratch.
    assert _scratch_ids(tmp_path) == ["obs-b", "obs-c"]
