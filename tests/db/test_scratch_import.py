"""
`chainsmith scratch-to-db`: scratch observations are imported once, and a row
already stored, superseded ones included, is not imported again.

The superseded case is the one the re-grade introduced: `apply_regrade` keeps a
replaced placeholder as `grading_state="superseded"`, and the default reads hide
those rows (`not_superseded()`). The importer must look at them anyway, or every
scratch copy of a superseded placeholder would come back as a fresh observation.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from click.testing import CliRunner

import app.db.engine as engine_mod
import app.db.writers as writers_mod
from app.cli import cli
from app.config import get_config
from app.db.engine import Database

pytestmark = pytest.mark.unit

SCAN = "scan-scratch-1"


def _obs(oid: str, title: str, **extra) -> dict:
    return {
        "id": oid,
        "title": title,
        "description": "d",
        "severity": "medium",
        "evidence": f"evidence for {title}",
        "check_name": "web_probe",
        "target_host": "www.example.com",
        **extra,
    }


async def _seed(db_path, rows):
    db = Database()
    await db.init(backend="sqlite", db_path=db_path)
    previous = engine_mod._default_db
    engine_mod._default_db = db
    try:
        from app.db.repositories import ObservationRepository

        await ObservationRepository().bulk_create(SCAN, rows)
    finally:
        engine_mod._default_db = previous
        await db.close()


async def _stored(db_path) -> list[dict]:
    db = Database()
    await db.init(backend="sqlite", db_path=db_path)
    previous = engine_mod._default_db
    engine_mod._default_db = db
    try:
        from app.db.repositories import ObservationRepository

        return await ObservationRepository().get_observations(SCAN, include_superseded=True)
    finally:
        engine_mod._default_db = previous
        await db.close()


@pytest.fixture
def env(tmp_path, monkeypatch):
    db_path = tmp_path / "chainsmith.db"
    scratch = tmp_path / "scratch"
    obs_dir = scratch / SCAN / "observations"
    obs_dir.mkdir(parents=True)

    storage = get_config().storage
    monkeypatch.setattr(storage, "backend", "sqlite")
    monkeypatch.setattr(storage, "db_path", db_path)
    monkeypatch.setattr(writers_mod, "scratch_dir", lambda: scratch)
    # The command initialises the default database itself; give it a fresh one.
    monkeypatch.setattr(engine_mod, "_default_db", Database())
    return db_path, obs_dir


def _write_scratch(obs_dir, *observations):
    for i, obs in enumerate(observations):
        (obs_dir / f"{i:04d}.json").write_text(json.dumps(obs), encoding="utf-8")


def test_a_superseded_row_is_not_imported_again(env):
    db_path, obs_dir = env
    placeholder = _obs("web_probe-www.example.com-a", "A", grading_state="superseded")
    asyncio.run(_seed(db_path, [placeholder]))

    _write_scratch(
        obs_dir,
        _obs("web_probe-www.example.com-a", "A", grading_state="ungraded"),  # same fingerprint
        _obs("web_probe-www.example.com-b", "B"),
    )

    result = CliRunner().invoke(cli, ["scratch-to-db", SCAN, "--keep"])

    assert result.exit_code == 0, result.output
    assert "1 new, 1 duplicates" in result.output
    titles = sorted(o["title"] for o in asyncio.run(_stored(db_path)))
    assert titles == ["A", "B"]


def test_duplicates_within_the_scratch_batch_import_once(env):
    db_path, obs_dir = env
    asyncio.run(_seed(db_path, []))
    same = _obs("web_probe-www.example.com-c", "C")
    _write_scratch(obs_dir, same, dict(same, id="web_probe-www.example.com-c2"))

    result = CliRunner().invoke(cli, ["scratch-to-db", SCAN, "--keep"])

    assert result.exit_code == 0, result.output
    assert "1 new, 1 duplicates" in result.output
    assert [o["title"] for o in asyncio.run(_stored(db_path))] == ["C"]


def test_dry_run_imports_nothing(env):
    db_path, obs_dir = env
    asyncio.run(_seed(db_path, []))
    _write_scratch(obs_dir, _obs("web_probe-www.example.com-d", "D"))

    result = CliRunner().invoke(cli, ["scratch-to-db", SCAN, "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "1 new, 0 duplicates" in result.output
    assert asyncio.run(_stored(db_path)) == []
    assert obs_dir.exists()


def test_a_colliding_id_with_different_content_is_renamed_not_fatal(env):
    """The writer sends a row to scratch when its id collides with a stored one.
    Importing it as-is used to fail the whole import on the unique key."""
    db_path, obs_dir = env
    asyncio.run(
        _seed(
            db_path,
            [_obs("web_probe-www.example.com-x", "X", target_url="https://www.example.com/a")],
        )
    )
    _write_scratch(
        obs_dir,
        _obs(
            "web_probe-www.example.com-x",
            "X",
            target_url="https://www.example.com/b",
            evidence="different evidence",
        ),
    )

    result = CliRunner().invoke(cli, ["scratch-to-db", SCAN, "--keep"])

    assert result.exit_code == 0, result.output
    assert "1 new, 0 duplicates, 1 renamed" in result.output
    ids = sorted(o["id"] for o in asyncio.run(_stored(db_path)))
    assert len(ids) == 2 and ids[0] != ids[1]
    assert all("web_probe-www.example.com-x" in i for i in ids)


def test_a_dict_without_host_still_matches_its_stored_row(env):
    db_path, obs_dir = env
    stored = _obs("web_probe-www.example.com-y", "Y")
    asyncio.run(_seed(db_path, [stored]))
    copy = {k: v for k, v in stored.items() if k != "host"}
    copy["host"] = None
    _write_scratch(obs_dir, copy)

    result = CliRunner().invoke(cli, ["scratch-to-db", SCAN, "--keep"])

    assert result.exit_code == 0, result.output
    assert "0 new, 1 duplicates" in result.output
