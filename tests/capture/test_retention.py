"""
Evidence retention (phase 57, D-5), and deleting a scan deletes its evidence.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest
from click.testing import CliRunner

from app import workspace as ws
from app.capture.retention import expired_scans, prune_evidence
from app.capture.store import EvidenceStore
from app.config import get_config
from app.grading import exchange_from_payload

pytestmark = pytest.mark.unit

DAY = 86400


@pytest.fixture(autouse=True)
def workspace(tmp_path):
    previous = ws.active()
    installed = ws.set_workspace(ws.Workspace(tmp_path / "ws").ensure())
    yield installed
    if previous is None:
        ws.reset_workspace()
    else:
        ws.set_workspace(previous)


def _capture(store: EvidenceStore, scan_id: str, age_days: float) -> None:
    exchange = exchange_from_payload("http", "h.test", check_name="c", scan_id=scan_id)
    path = store.write(exchange)
    store.write_grading_record(scan_id, "c", {"version": 2, "candidates": []})
    stamp = time.time() - age_days * DAY
    for f in store.scan_dir(scan_id).rglob("*"):
        if f.is_file():
            os.utime(f, (stamp, stamp))
    assert path.exists()


def test_only_scans_past_the_cutoff_expire():
    store = EvidenceStore()
    _capture(store, "old-scan", 40)
    _capture(store, "new-scan", 2)
    assert expired_scans(store, 30) == ["old-scan"]
    assert expired_scans(store, 0) == []


def test_a_dry_run_removes_nothing():
    store = EvidenceStore()
    _capture(store, "old-scan", 40)

    result = asyncio.run(prune_evidence(30, store=store, dry_run=True))

    assert result.scans == ["old-scan"] and result.documents == 0
    assert store.scan_dir("old-scan").exists()


def test_prune_removes_documents_and_grading_records_only_for_old_scans():
    store = EvidenceStore()
    _capture(store, "old-scan", 40)
    _capture(store, "new-scan", 2)

    result = asyncio.run(prune_evidence(30, store=store))

    assert result.scans == ["old-scan"] and result.documents == 1
    assert not store.scan_dir("old-scan").exists()
    assert store.read_scan("new-scan") and store.read_grading_records("new-scan")


def test_zero_days_means_keep_for_the_workspace_lifetime(monkeypatch):
    store = EvidenceStore()
    _capture(store, "old-scan", 4000)
    monkeypatch.setattr(get_config().storage, "evidence_retention_days", 0)

    result = asyncio.run(prune_evidence(store=store))

    assert result.scans == [] and store.scan_dir("old-scan").exists()


def test_the_default_comes_from_config(monkeypatch):
    store = EvidenceStore()
    _capture(store, "old-scan", 40)
    monkeypatch.setattr(get_config().storage, "evidence_retention_days", 30)

    assert asyncio.run(prune_evidence(store=store, dry_run=True)).scans == ["old-scan"]


def test_the_cli_reports_off_and_dry_run(monkeypatch):
    from app.cli import cli

    monkeypatch.setattr(get_config().storage, "evidence_retention_days", 0)
    off = CliRunner().invoke(cli, ["evidence", "prune"])
    assert off.exit_code == 0 and "retention is off" in off.output

    _capture(EvidenceStore(), "old-scan", 40)
    dry = CliRunner().invoke(cli, ["evidence", "prune", "--older-than", "30", "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert "Would remove evidence for 1 scan(s)" in dry.output and "old-scan" in dry.output
    assert EvidenceStore().scan_dir("old-scan").exists()


def test_deleting_a_scan_deletes_its_evidence_documents(monkeypatch):
    from app.routes import scan_history

    store = EvidenceStore()
    _capture(store, "gone-scan", 1)

    async def deleted(scan_id):
        return True

    monkeypatch.setattr(scan_history._scan_repo, "delete_scan", deleted)

    response = asyncio.run(scan_history.delete_scan("gone-scan"))

    assert response["deleted"] is True and response["evidence_removed"] == 1
    assert not store.scan_dir("gone-scan").exists()
