"""
The offline re-grade pass — Phase 57 success criteria 2 and 4 (§10).

Criterion 4 ends "a later re-grade pass fills them in without re-scanning";
criterion 2 asks that re-grading a stored corpus produce "an inspectable diff
against the original". Both are claims about a scan that already happened, so
every test here runs a scan first — through `grade_result()` or through
`CheckLauncher.run_all()`, the way a real one does — and only then re-grades.

What is held to:

- A capturing scan leaves a grading record; a non-capturing one does not.
- A re-grade reads the workspace and nothing else: no socket, no write.
- An unchanged grader reproduces the scan; a changed one shows as a field diff.
- A placeholder the re-grade fills in under a *different* id is superseded,
  never deleted; one filled in under the same id is simply changed.
- Evidence that never reached the corpus is skipped and named.
"""

import asyncio
import socket

import pytest

import app.db.engine as _engine_module
from app import workspace as ws
from app.capture.settings import CaptureSettings
from app.capture.store import EvidenceStore
from app.check_launcher import CheckLauncher
from app.checks.base import CheckResult, Service
from app.db.engine import Database
from app.db.repositories import (
    ComparisonRepository,
    ObservationRepository,
    ScanRepository,
    scoped_observation_id,
)
from app.grading import Candidate, GradingState, Verdict, exchange_from_payload, grade_result
from app.grading import regrade as regrade_module
from app.grading.record import restore_context, snapshot_context
from app.grading.regrade import ChangeKind, apply_regrade, regrade_scan, render_report

pytestmark = pytest.mark.unit

SCAN = "scan-regrade-0001"
HOST = "acme.test"


# ── fixtures ─────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def workspace(tmp_path):
    """A real workspace under tmp_path, so the default EvidenceStore is used."""
    previous = ws.active()
    installed = ws.set_workspace(ws.Workspace(tmp_path / "ws").ensure())
    yield installed
    if previous is None:
        ws.reset_workspace()
    else:
        ws.set_workspace(previous)


@pytest.fixture
async def db(tmp_path):
    database = Database()
    await database.init(backend="sqlite", db_path=tmp_path / "test.db")
    old_default = _engine_module._default_db
    _engine_module._default_db = database
    yield database
    _engine_module._default_db = old_default
    await database.close()


class FakeCheck:
    """A migrated check in miniature.

    Its probe records one exchange into the corpus — what the HTTP interceptor
    does under `--capture` — and hands the same exchange to one candidate. The
    grader is configurable, so a test can change it between the scan and the
    re-grade, which is the whole case a re-grade exists for.
    """

    def __init__(
        self,
        name="web_regrade",
        *,
        verdict_severity="medium",
        discriminator="subject",
        raises=False,
        reads_context=False,
        in_corpus=True,
    ):
        self.name = name
        self.produces = []
        self.conditions = []
        self.verdict_severity = verdict_severity
        self.discriminator = discriminator
        self.raises = raises
        self.reads_context = reads_context
        self.in_corpus = in_corpus
        self.seen_context = None

    async def execute(self, context):
        exchange = exchange_from_payload(
            "http",
            HOST,
            check_name=self.name,
            scan_id=context.get("scan_id", ""),
            request_body="GET /",
            response_body="Server: nginx",
        )
        if self.in_corpus:
            EvidenceStore().write(exchange)
        candidate = Candidate(
            check_name=self.name,
            host=HOST,
            provisional_severity="low",
            discriminator="subject",
            target=Service(url=f"https://{HOST}", host=HOST, port=443, scheme="https"),
            raw_data={"path": "/"},
        )
        candidate.attach(exchange)
        return CheckResult(success=True, candidates=[candidate])

    def grade(self, evidence, ctx):
        self.seen_context = ctx.context
        if self.raises:
            raise RuntimeError("grader blew up")
        severity = self.verdict_severity
        if self.reads_context:
            severity = ctx.context["severity_hint"]
        return Verdict(
            severity=severity,
            confidence=0.8,
            discriminator=self.discriminator,
            title=f"{self.name} verdict",
            reasoning="the recorded response says so",
            tier=ctx.tier,
            evidence_ids=evidence.ids(),
        )


def _capturing(**extra):
    return {"scan_id": SCAN, "capture_settings": CaptureSettings(enabled=True), **extra}


def _stored(record: dict) -> dict:
    """A record as the observations table hands it back: id scoped per scan."""
    return {**record, "id": scoped_observation_id(SCAN, record["id"])}


async def _scan(check, *, capture=True, **context_extra) -> list[dict]:
    """Run one check the way a scan does; return what the table would hold."""
    context = _capturing(**context_extra)
    if not capture:
        context["capture_settings"] = CaptureSettings(enabled=False)
    result = await check.execute(context)
    await grade_result(check, result, context)
    return [
        _stored({**obs.to_dict(), "raw_data": dict(obs.raw_data or {})})
        for obs in result.observations
    ]


async def _regrade(check, stored_rows, **kwargs):
    return await regrade_scan(SCAN, stored_rows, resolve_check={check.name: check}.get, **kwargs)


def _kinds(report):
    return sorted(str(change.kind) for change in report.changes)


def _evidence_snapshot(root):
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*.json"))
    }


# ── the scan-time grading record ─────────────────────────────────────


class TestGradingRecord:
    async def test_a_capturing_scan_leaves_a_record_referencing_its_exchanges(self):
        await _scan(FakeCheck())

        [record] = EvidenceStore().read_grading_records(SCAN)
        exchange = EvidenceStore().read_scan(SCAN)[0]

        assert record["check_name"] == "web_regrade"
        assert record["scan_id"] == SCAN
        [candidate] = record["candidates"]
        assert candidate["exchanges"] == [exchange.content_hash]
        assert candidate["discriminator"] == "subject"
        assert candidate["target"]["host"] == HOST
        assert record["version"] == 2
        assert "capture_settings" not in record["context_refs"]

    async def test_a_context_value_is_stored_once_however_many_checks_see_it(self):
        await _scan(FakeCheck("web_one"), dns_records={"a": "1.2.3.4"})
        await _scan(FakeCheck("web_two"), dns_records={"a": "1.2.3.4"})
        store = EvidenceStore()

        one, two = store.read_grading_records(SCAN)
        values = list(store.context_dir(SCAN).glob("*.json"))

        assert one["context_refs"]["dns_records"] == two["context_refs"]["dns_records"]
        # scan_id, dns_records: one file each, shared by both records.
        assert len(values) == len(one["context_refs"])
        assert not (store.grading_dir(SCAN) / "web_one.json").read_text().startswith("{\n")

    async def test_a_version_1_record_still_replays(self):
        check = FakeCheck(reads_context=True)
        stored = await _scan(check, severity_hint="critical")
        store = EvidenceStore()
        [record] = store.read_grading_records(SCAN)
        snapshot, _ = regrade_module.context_from_record(record, store, SCAN)
        legacy = {k: v for k, v in record.items() if k != "context_refs"}
        store.write_grading_record(SCAN, check.name, {**legacy, "version": 1, "context": snapshot})

        report = await _regrade(FakeCheck(reads_context=True), stored)

        assert _kinds(report) == ["unchanged"]

    async def test_a_missing_context_value_skips_the_check_and_names_the_key(self):
        stored = await _scan(FakeCheck(reads_context=True), severity_hint="critical")
        store = EvidenceStore()
        [record] = store.read_grading_records(SCAN)
        (store.context_dir(SCAN) / f"{record['context_refs']['severity_hint']}.json").unlink()

        report = await _regrade(FakeCheck(reads_context=True), stored)

        assert report.changes == []
        [skip] = report.skipped
        assert "severity_hint" in skip.reason

    async def test_a_scan_without_capture_leaves_no_record(self):
        await _scan(FakeCheck(), capture=False)

        assert EvidenceStore().read_grading_records(SCAN) == []

    async def test_the_record_is_written_even_when_the_grader_raises(self):
        """So a fixed grader has something to replay later."""
        await _scan(FakeCheck(raises=True))

        assert len(EvidenceStore().read_grading_records(SCAN)) == 1

    def test_unserialisable_context_is_dropped_and_named_not_guessed(self):
        snapshot, dropped = snapshot_context(
            {"dns_records": {"a": "1.2.3.4"}, "weird": object(), "tags": {"b", "a"}}
        )

        assert snapshot == {"dns_records": {"a": "1.2.3.4"}, "tags": ["a", "b"]}
        assert dropped == ["weird"]

    def test_services_come_back_as_service_objects(self):
        service = Service(url="https://acme.test", host=HOST, port=443, scheme="https")
        snapshot, _ = snapshot_context({"services": [service]})

        [restored] = restore_context(snapshot)["services"]

        assert isinstance(restored, Service)
        assert restored.host == HOST

    def test_deleting_a_scan_removes_its_grading_records(self):
        asyncio.run(_scan(FakeCheck()))
        store = EvidenceStore()

        assert store.delete_scan(SCAN) == 1
        assert not store.scan_dir(SCAN).exists()


# ── criterion 2: an inspectable diff ─────────────────────────────────


class TestDiff:
    async def test_an_unchanged_grader_reproduces_the_scan(self):
        check = FakeCheck()
        stored = await _scan(check)

        report = await _regrade(check, stored)

        assert _kinds(report) == ["unchanged"]
        assert report.has_changes is False
        assert report.checks == ["web_regrade"]

    async def test_a_changed_grader_shows_as_a_field_diff(self):
        stored = await _scan(FakeCheck(verdict_severity="medium"))

        report = await _regrade(FakeCheck(verdict_severity="high"), stored)

        [change] = report.changes
        assert change.kind == ChangeKind.CHANGED
        assert change.fields == {"severity": ("medium", "high")}
        assert "severity: 'medium' -> 'high'" in render_report(report)

    async def test_a_context_reading_grader_regrades_against_the_scans_context(self):
        service = Service(url="https://acme.test", host=HOST, port=443, scheme="https")
        stored = await _scan(
            FakeCheck(reads_context=True), severity_hint="critical", services=[service]
        )

        check = FakeCheck(reads_context=True)
        report = await _regrade(check, stored)

        assert _kinds(report) == ["unchanged"]
        assert check.seen_context["severity_hint"] == "critical"
        assert isinstance(check.seen_context["services"][0], Service)

    async def test_a_graded_row_the_regrade_does_not_reproduce_is_flagged_not_superseded(self):
        stored = await _scan(FakeCheck(discriminator="a"))

        report = await _regrade(FakeCheck(discriminator="b"), stored)

        assert _kinds(report) == ["added", "not_reproduced"]

    async def test_evidence_that_never_reached_the_corpus_is_skipped_and_named(self):
        stored = await _scan(FakeCheck(in_corpus=False))

        report = await _regrade(FakeCheck(verdict_severity="high"), stored)

        assert report.changes == []
        assert report.checks == []
        [skip] = report.skipped
        assert "not in the corpus" in skip.reason

    async def test_a_check_no_longer_in_the_tree_is_skipped(self):
        stored = await _scan(FakeCheck())

        report = await regrade_scan(SCAN, stored, resolve_check=lambda name: None)

        [skip] = report.skipped
        assert skip.candidate_id is None
        assert "not in this tree" in skip.reason

    def test_the_default_resolver_finds_real_migrated_checks(self):
        """Every other test injects its resolver; this one is what the CLI uses."""
        check = regrade_module._default_resolver()("web_header_analysis")

        assert check is not None
        assert callable(getattr(check, "grade", None))

    async def test_only_limits_the_pass_to_named_checks(self):
        stored = await _scan(FakeCheck())

        report = await _regrade(FakeCheck(), stored, only=["web_something_else"])

        assert report.records_found == 0
        assert report.changes == []

    async def test_a_regrade_touches_neither_the_network_nor_the_workspace(
        self, monkeypatch, workspace
    ):
        stored = await _scan(FakeCheck())
        before = _evidence_snapshot(workspace.evidence_dir)

        def refuse(*args, **kwargs):
            raise AssertionError("a re-grade opened a connection")

        monkeypatch.setattr(socket.socket, "connect", refuse)
        report = await _regrade(FakeCheck(verdict_severity="high"), stored)

        assert report.has_changes is True
        assert _evidence_snapshot(workspace.evidence_dir) == before


# ── criterion 4: a later re-grade fills them in ──────────────────────


class TestFillingIn:
    async def test_a_failed_placeholder_graded_under_the_same_id_is_changed(self):
        stored = await _scan(FakeCheck(raises=True))
        assert stored[0]["grading_state"] == GradingState.GRADING_FAILED

        report = await _regrade(FakeCheck(), stored)

        [change] = report.changes
        assert change.kind == ChangeKind.CHANGED
        assert change.fields["grading_state"] == ("grading_failed", "graded")
        assert change.fields["severity"] == ("low", "medium")

    async def test_a_placeholder_graded_under_a_different_id_is_superseded(self):
        stored = await _scan(FakeCheck(raises=True))

        report = await _regrade(FakeCheck(discriminator="other"), stored)

        assert _kinds(report) == ["added", "superseded"]
        [added] = report.of_kind(ChangeKind.ADDED)
        [superseded] = report.of_kind(ChangeKind.SUPERSEDED)
        assert superseded.superseded_by == [added.observation_id]

    async def test_end_to_end_through_the_launcher(self):
        """The criterion as stated: a scan whose grader failed, then a re-grade."""
        launcher = CheckLauncher([FakeCheck("web_broken", raises=True)], _capturing())
        records = await launcher.run_all()
        assert records[0]["grading_state"] == GradingState.GRADING_FAILED

        report = await _regrade(FakeCheck("web_broken"), [_stored(r) for r in records])

        [change] = report.changes
        assert change.kind == ChangeKind.CHANGED
        assert change.fields["grading_state"] == ("grading_failed", "graded")


# ── --apply ──────────────────────────────────────────────────────────


class TestApply:
    async def _persisted_scan(self, check):
        await ScanRepository().create_scan(SCAN, "session-1", HOST)
        context = _capturing()
        result = await check.execute(context)
        await grade_result(check, result, context)
        await ObservationRepository().bulk_create(
            SCAN,
            [
                {**obs.to_dict(), "raw_data": dict(obs.raw_data or {})}
                for obs in result.observations
            ],
        )

    async def test_a_changed_verdict_is_written_in_place(self, db):
        await self._persisted_scan(FakeCheck(verdict_severity="medium"))
        repo = ObservationRepository()

        report = await _regrade(FakeCheck(verdict_severity="high"), await repo.get_records(SCAN))
        counts = await apply_regrade(report)

        assert counts["updated"] == 1
        [row] = await repo.get_records(SCAN)
        assert row["severity"] == "high"
        assert row["provisional_severity"] == "low"

    async def test_apply_supersedes_but_never_deletes_and_is_idempotent(self, db):
        await self._persisted_scan(FakeCheck(raises=True))
        repo = ObservationRepository()
        fixed = FakeCheck(discriminator="other")

        report = await _regrade(fixed, await repo.get_records(SCAN))
        counts = await apply_regrade(report)

        assert (counts["updated"], counts["inserted"], counts["superseded"]) == (0, 1, 1)
        rows = {row["id"]: row for row in await repo.get_records(SCAN)}
        assert len(rows) == 2
        [superseded] = report.of_kind(ChangeKind.SUPERSEDED)
        [added] = report.of_kind(ChangeKind.ADDED)
        assert rows[superseded.observation_id]["grading_state"] == "superseded"
        assert added.observation_id in rows[superseded.observation_id]["grading_reasoning"]
        assert rows[added.observation_id]["grading_state"] == "graded"
        assert rows[superseded.observation_id]["raw_data"]["superseded_by"] == [
            added.observation_id
        ]
        # Default reads count the successor only; the scan never completed, so
        # it has no status history to rebuild.
        assert [row["id"] for row in await repo.get_observations(SCAN)] == [added.observation_id]
        assert counts["statuses_recomputed"] == 0

        again = await _regrade(fixed, await repo.get_records(SCAN))
        assert again.has_changes is False

    async def test_apply_rebuilds_the_scans_status_history(self, db):
        await self._persisted_scan(FakeCheck(raises=True))
        await ScanRepository().complete_scan(SCAN, status="complete", observations_count=1)
        comparisons = ComparisonRepository()
        await comparisons.compute_observation_statuses(SCAN)
        repo = ObservationRepository()
        [placeholder] = await repo.get_records(SCAN)
        assert await comparisons.get_observation_history(placeholder["fingerprint"])

        report = await _regrade(FakeCheck(discriminator="other"), await repo.get_records(SCAN))
        counts = await apply_regrade(report)

        assert counts["statuses_recomputed"] == 1
        [successor] = await repo.get_observations(SCAN)
        assert await comparisons.get_observation_history(placeholder["fingerprint"]) == []
        [entry] = await comparisons.get_observation_history(successor["fingerprint"])
        assert (entry["scan_id"], entry["status"]) == (SCAN, "new")


# ── the CLI ──────────────────────────────────────────────────────────


class TestCli:
    @pytest.fixture(autouse=True)
    def no_database(self, monkeypatch):
        """The command's wiring, not the database: never open a real one."""
        import app.db

        async def fake_init_db(**_):
            return None

        monkeypatch.setattr(app.db, "init_db", fake_init_db)

    def _invoke(self, workspace, *args):
        from click.testing import CliRunner

        from app.cli import cli

        return CliRunner().invoke(
            cli, ["--workspace", str(workspace.root), "dev", "regrade", *args]
        )

    def test_an_unknown_scan_exits_1(self, monkeypatch, workspace):
        async def no_scan(self, scan_id):
            return None

        monkeypatch.setattr(ScanRepository, "get_scan", no_scan)

        result = self._invoke(workspace, "nope")

        assert result.exit_code == 1
        assert "No scan 'nope'" in result.output

    def test_a_scan_with_no_grading_records_exits_1(self, monkeypatch, workspace):
        async def a_scan(self, scan_id):
            return {"id": scan_id}

        async def no_rows(self, scan_id):
            return []

        monkeypatch.setattr(ScanRepository, "get_scan", a_scan)
        monkeypatch.setattr(ObservationRepository, "get_records", no_rows)

        result = self._invoke(workspace, SCAN)

        assert result.exit_code == 1
        assert "No grading records" in result.output

    def test_a_dry_run_prints_the_diff_and_writes_nothing(self, monkeypatch, workspace):
        stored = asyncio.run(_scan(FakeCheck(verdict_severity="medium")))
        before = _evidence_snapshot(workspace.evidence_dir)

        async def a_scan(self, scan_id):
            return {"id": scan_id}

        async def rows(self, scan_id):
            return stored

        monkeypatch.setattr(ScanRepository, "get_scan", a_scan)
        monkeypatch.setattr(ObservationRepository, "get_records", rows)
        monkeypatch.setattr(
            regrade_module,
            "_default_resolver",
            lambda: {"web_regrade": FakeCheck(verdict_severity="high")}.get,
        )

        result = self._invoke(workspace, SCAN)

        assert result.exit_code == 0, result.output
        assert "CHANGED" in result.output
        assert "severity: 'medium' -> 'high'" in result.output
        assert "Dry run" in result.output
        assert _evidence_snapshot(workspace.evidence_dir) == before


# ── the D-2 id-collision guard ───────────────────────────────────────


class TwoEndpointCheck(FakeCheck):
    """Two candidates on one host whose verdicts share a discriminator, so the
    second observation id collides with the first at scan time."""

    async def execute(self, context):
        candidates = []
        for path in ("/chat", "/v1/chat"):
            exchange = exchange_from_payload(
                "http",
                HOST,
                check_name=self.name,
                scan_id=context.get("scan_id", ""),
                request_body=f"POST {path}",
                response_body="leaked",
            )
            EvidenceStore().write(exchange)
            url = f"https://{HOST}{path}"
            candidate = Candidate(
                check_name=self.name,
                host=HOST,
                provisional_severity="low",
                discriminator="subject",
                target=Service(url=url, host=HOST, port=443, scheme="https"),
                target_url=url,
            )
            candidate.attach(exchange)
            candidates.append(candidate)
        return CheckResult(success=True, candidates=candidates)


class TestIdCollisionGuard:
    async def test_a_regrade_reproduces_the_renamed_ids(self):
        check = TwoEndpointCheck()
        stored = await _scan(check)
        assert len({row["id"] for row in stored}) == 2

        report = await _regrade(check, stored)

        assert _kinds(report) == ["unchanged", "unchanged"]
        assert report.has_changes is False
