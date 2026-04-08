"""Tests for targeted export from selected observations."""

import json

import pytest

from app.db.models import ObservationRecord
from app.reports import generate_targeted_export

from .conftest import _create_populated_scan

pytestmark = pytest.mark.integration


@pytest.fixture
async def targeted_setup(db, scan_repo, observation_repo, chain_repo, check_log_repo):
    """Set up a scan with observations and return (fingerprints, db)."""
    await _create_populated_scan(
        scan_repo,
        observation_repo,
        chain_repo,
        check_log_repo,
        scan_id="sarif-scan",
        target="example.com",
    )
    from sqlalchemy import select

    async with db.session() as session:
        result = await session.execute(select(ObservationRecord.fingerprint))
        fps = [row[0] for row in result.all()]
    return fps, db


async def test_targeted_markdown_export(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(fps[:2], "md", db=db)

    assert result["format"] == "md"
    assert result["filename"].startswith("targeted-export-")
    assert result["filename"].endswith(".md")
    content = result["content"]
    assert "# Targeted Export" in content
    assert "**Observations:** 2" in content


async def test_targeted_json_export(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(fps, "json", db=db)

    assert result["format"] == "json"
    report = json.loads(result["content"])
    assert report["report_type"] == "targeted"
    assert report["summary"]["total_observations"] == 4


async def test_targeted_html_export(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(fps, "html", db=db)

    assert result["format"] == "html"
    assert "<!DOCTYPE html>" in result["content"]
    assert "Targeted Export" in result["content"]


async def test_targeted_sarif_export(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(fps, "sarif", db=db)

    assert result["format"] == "sarif"
    sarif = json.loads(result["content"])
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 4
    props = sarif["runs"][0]["invocations"][0]["properties"]
    assert props["reportType"] == "targeted"


async def test_targeted_custom_title(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(
        fps[:1], "md", title="Critical Observations Only", db=db
    )
    assert "# Critical Observations Only" in result["content"]


async def test_targeted_no_observations_raises(db):
    with pytest.raises(ValueError, match="No observations found"):
        await generate_targeted_export(["nonexistent-fp"], "md", db=db)


async def test_targeted_risk_score_calculation(targeted_setup):
    fps, db = targeted_setup
    result = await generate_targeted_export(fps, "json", db=db)
    report = json.loads(result["content"])
    # 1 critical(10) + 1 high(5) + 1 medium(2) + 1 info(0) = 17
    assert report["summary"]["risk_score"] == 17
