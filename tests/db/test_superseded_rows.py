"""
Superseded rows at the data layer — the phase 57 re-grade follow-up (S-1, S-2, S-5).

`regrade --apply` keeps a placeholder it replaced, marked `superseded`, beside
the successor it inserted. Every read that counts must leave the placeholder out
— its successor is already there — and status history computed before the
re-grade must be rebuilt. What is held to:

- Default reads exclude superseded rows, the flag includes them, and a row whose
  grading_state is NULL (from before 57.3) is kept either way.
- Comparison and trend never see a superseded fingerprint.
- `compute_observation_statuses` is safe to rerun and never pairs a scan with a
  later one; `recompute_statuses_from` rebuilds a scan and every later scan of
  its target, and nothing earlier.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update

import app.db.engine as _engine_module
from app.db.engine import Database
from app.db.models import ObservationRecord, ObservationStatusHistory, Scan, ScanComparison
from app.db.repositories import (
    SUPERSEDED_STATE,
    ComparisonRepository,
    ObservationRepository,
    TrendRepository,
    _generate_fingerprint,
    scoped_observation_id,
)
from app.grading.models import GradingState
from app.lib.observations import (
    is_placeholder,
    partition_by_grading,
    resolve_superseded_ids,
    supersession_note,
)

pytestmark = pytest.mark.integration

TARGET = "acme.test"
T0 = datetime(2026, 9, 1, tzinfo=UTC)


@pytest.fixture
async def db(tmp_path):
    database = Database()
    await database.init(backend="sqlite", db_path=tmp_path / "test.db")
    old_default = _engine_module._default_db
    _engine_module._default_db = database
    yield database
    _engine_module._default_db = old_default
    await database.close()


def _obs(key: str, **extra) -> dict:
    """A check-shaped observation. Same key, same fingerprint, in any scan."""
    return {
        "id": key,
        "title": f"{key} title",
        "severity": "medium",
        "check_name": "web_regrade",
        "host": TARGET,
        "evidence": f"{key} evidence",
        "grading_state": "graded",
        **extra,
    }


def _fp(key: str) -> str:
    return _generate_fingerprint("web_regrade", TARGET, f"{key} title", f"{key} evidence")


async def _scan(db, scan_id, *, hours=0, observations=(), status="complete"):
    """A scan with an explicit start time, so ordering never rests on a clock tick."""
    async with db.session() as session:
        session.add(
            Scan(
                id=scan_id,
                session_id="s",
                target_domain=TARGET,
                status=status,
                started_at=T0 + timedelta(hours=hours),
                observations_count=len(observations),
            )
        )
        await session.commit()
    await ObservationRepository(db).bulk_create(scan_id, list(observations))


async def _supersede(db, scan_id, placeholder: str, successor: dict) -> dict:
    """What `regrade --apply` writes: the placeholder marked, its successor inserted."""
    placeholder_id = scoped_observation_id(scan_id, placeholder)
    successor_id = scoped_observation_id(scan_id, successor["id"])
    return await ObservationRepository(db).apply_regrade(
        scan_id,
        changed=[],
        added=[successor],
        superseded={placeholder_id: f"Superseded by offline re-grade: {successor_id}"},
        successors={placeholder_id: [successor_id]},
    )


async def _statuses(db, scan_id) -> set[tuple[str, str]]:
    async with db.session() as session:
        result = await session.execute(
            select(ObservationStatusHistory.fingerprint, ObservationStatusHistory.status).where(
                ObservationStatusHistory.scan_id == scan_id
            )
        )
        return {(fp, status) for fp, status in result.all()}


# ── the shared helpers ───────────────────────────────────────────────


class TestHelpers:
    def test_the_data_layer_spells_the_state_the_grading_package_defines(self):
        assert SUPERSEDED_STATE == GradingState.SUPERSEDED

    def test_partition_splits_off_superseded_rows_and_states_them(self):
        rows = [
            {"id": "a", "grading_state": "graded"},
            {"id": "b", "grading_state": "superseded"},
            {"id": "c", "grading_state": None},
        ]

        current, superseded = partition_by_grading(rows)

        assert [r["id"] for r in current] == ["a", "c"]
        assert [r["id"] for r in superseded] == ["b"]
        assert supersession_note(superseded) == "1 observation superseded by re-grade"
        assert supersession_note(superseded * 2) == "2 observations superseded by re-grade"
        assert supersession_note([]) == ""

    def test_a_placeholder_is_ungraded_or_failed_and_never_superseded(self):
        assert is_placeholder({"grading_state": None})
        assert is_placeholder({"grading_state": "grading_failed"})
        assert not is_placeholder({"grading_state": "superseded"})
        assert not is_placeholder({"grading_state": "graded"})

    def test_chain_ids_render_through_to_successors(self):
        superseded = [
            {"id": "p1", "raw_data": {"superseded_by": ["s1", "s2"]}},
            {"id": "p2", "raw_data": {"superseded_by": []}},
        ]

        resolved = resolve_superseded_ids(["p1", "g", "s1", "p2"], superseded)

        # Successors in place, a repeat named once, a no-verdict id kept.
        assert resolved == ["s1", "s2", "g", "p2"]


# ── S-1: the repository default ──────────────────────────────────────


class TestDefaultReads:
    async def test_superseded_rows_are_excluded_by_default_and_included_on_request(self, db):
        await _scan(db, "scan-a", observations=[_obs("g"), _obs("p", grading_state="ungraded")])
        counts = await _supersede(db, "scan-a", "p", _obs("s"))
        repo = ObservationRepository(db)

        default = {row["id"] for row in await repo.get_observations("scan-a")}
        everything = await repo.get_observations("scan-a", include_superseded=True)
        [host] = await repo.get_observations_by_host("scan-a")

        assert counts["superseded"] == 1
        assert default == {scoped_observation_id("scan-a", k) for k in ("g", "s")}
        assert len(everything) == 3
        assert len(host["observations"]) == 2

    async def test_the_successors_are_recorded_on_the_superseded_row(self, db):
        await _scan(
            db, "scan-a", observations=[_obs("p", grading_state="ungraded", raw_data={"k": 1})]
        )
        await _supersede(db, "scan-a", "p", _obs("s"))

        [row] = [
            r
            for r in await ObservationRepository(db).get_records("scan-a")
            if r["grading_state"] == "superseded"
        ]

        assert row["raw_data"] == {"k": 1, "superseded_by": [scoped_observation_id("scan-a", "s")]}

    async def test_a_row_with_no_grading_state_is_never_dropped(self, db):
        """`grading_state != 'superseded'` is not true for NULL in SQL."""
        await _scan(db, "scan-a", observations=[_obs("legacy")])
        async with db.session() as session:
            await session.execute(update(ObservationRecord).values(grading_state=None))
            await session.commit()
        repo = ObservationRepository(db)

        assert len(await repo.get_observations("scan-a")) == 1
        assert len(await repo.get_observations("scan-a", include_superseded=True)) == 1
        assert len((await repo.get_observations_by_host("scan-a"))[0]["observations"]) == 1


# ── comparison ───────────────────────────────────────────────────────


class TestComparison:
    async def test_a_superseded_fingerprint_is_neither_new_nor_resolved(self, db):
        await _scan(db, "scan-1", hours=0, observations=[_obs("g"), _obs("s")])
        await _scan(
            db, "scan-2", hours=1, observations=[_obs("g"), _obs("p", grading_state="ungraded")]
        )
        await _supersede(db, "scan-2", "p", _obs("s"))
        comparisons = ComparisonRepository(db)

        live = await comparisons.compare_scans("scan-1", "scan-2")
        stats = await comparisons.compute_observation_statuses("scan-2")

        assert (live["new_count"], live["resolved_count"], live["recurring_count"]) == (0, 0, 2)
        assert (stats["new"], stats["resolved"], stats["recurring"]) == (0, 0, 2)

    async def test_rerunning_status_computation_replaces_rather_than_appends(self, db):
        await _scan(db, "scan-1", hours=0, observations=[_obs("g")])
        await _scan(db, "scan-2", hours=1, observations=[_obs("g")])
        comparisons = ComparisonRepository(db)

        await comparisons.compute_observation_statuses("scan-2")
        await comparisons.compute_observation_statuses("scan-2")

        assert await _statuses(db, "scan-2") == {(_fp("g"), "recurring")}
        async with db.session() as session:
            result = await session.execute(
                select(func.count())
                .select_from(ScanComparison)
                .where(ScanComparison.scan_b_id == "scan-2")
            )
            assert result.scalar() == 1

    async def test_the_previous_scan_is_never_a_later_one(self, db):
        await _scan(db, "scan-1", hours=0, observations=[_obs("g")])
        await _scan(db, "scan-2", hours=1, observations=[_obs("g")])

        stats = await ComparisonRepository(db).compute_observation_statuses("scan-1")

        assert stats["previous_scan_id"] is None
        assert await _statuses(db, "scan-1") == {(_fp("g"), "new")}


# ── S-5: the cascade ─────────────────────────────────────────────────


class TestCascade:
    async def test_a_regrade_rebuilds_this_scan_and_every_later_one(self, db):
        await _scan(db, "scan-0", hours=-1, observations=[_obs("g")])
        await _scan(
            db, "scan-1", hours=0, observations=[_obs("g"), _obs("p", grading_state="ungraded")]
        )
        await _scan(db, "scan-2", hours=1, observations=[_obs("g"), _obs("s")])
        await _scan(db, "scan-3", hours=2, observations=[_obs("g"), _obs("s")])
        comparisons = ComparisonRepository(db)
        for scan_id in ("scan-0", "scan-1", "scan-2", "scan-3"):
            await comparisons.compute_observation_statuses(scan_id)
        # The phantom the re-grade must remove: scan-2 "resolved" the placeholder.
        assert (_fp("p"), "resolved") in await _statuses(db, "scan-2")

        await _supersede(db, "scan-1", "p", _obs("s"))
        recomputed = await comparisons.recompute_statuses_from("scan-1")

        assert recomputed == ["scan-1", "scan-2", "scan-3"]
        assert await _statuses(db, "scan-0") == {(_fp("g"), "new")}
        assert await _statuses(db, "scan-1") == {(_fp("g"), "recurring"), (_fp("s"), "new")}
        assert await _statuses(db, "scan-2") == {(_fp("g"), "recurring"), (_fp("s"), "recurring")}
        assert await _statuses(db, "scan-3") == {(_fp("g"), "recurring"), (_fp("s"), "recurring")}
        async with db.session() as session:
            result = await session.execute(select(func.count()).select_from(ScanComparison))
            assert result.scalar() == 3

    async def test_a_scan_that_never_completed_rebuilds_nothing(self, db):
        await _scan(db, "scan-1", observations=[_obs("g")], status="running")

        assert await ComparisonRepository(db).recompute_statuses_from("scan-1") == []


# ── trend ────────────────────────────────────────────────────────────


class TestTrend:
    async def test_trend_totals_leave_superseded_rows_out(self, db):
        await _scan(
            db,
            "scan-1",
            observations=[_obs("g"), _obs("p", grading_state="ungraded", severity="critical")],
        )
        await _supersede(db, "scan-1", "p", _obs("s"))

        trend = await TrendRepository(db).get_target_trend(TARGET)

        [point] = trend["data_points"]
        assert (point["total"], point["critical"], point["medium"]) == (2, 0, 2)
        assert point["risk_score"] == 4
