"""
Reports over a re-graded scan — the phase 57 re-grade follow-up (S-2, S-3, S-6).

A scan whose failed placeholder an offline re-grade replaced holds both rows:
the placeholder, now `superseded`, and its successor. The placeholder is
provisionally critical and the successor high, so a report that counted both
would show it in the risk score. What is held to:

- Severity counts and risk are the counts with the placeholder removed.
- The technical report states it (a note and an appendix naming the successor),
  never labels it ungraded, and renders a chain through to the successor.
- Executive and compliance state the count only; CSV and SARIF omit the row.
- The targeted export never picks a superseded row for a fingerprint.
"""

import json

import pytest
from sqlalchemy import select

from app.db.models import ObservationRecord
from app.db.repositories import scoped_observation_id
from app.reports import (
    generate_compliance_report,
    generate_executive_report,
    generate_targeted_export,
    generate_technical_report,
)

pytestmark = pytest.mark.integration

SCAN = "regraded-scan"
PLACEHOLDER = scoped_observation_id(SCAN, "web_regrade-example.com-subject")
SUCCESSOR = scoped_observation_id(SCAN, "web_regrade-example.com-other")
SQLI = scoped_observation_id(SCAN, "sqli-example.com")
PLACEHOLDER_TITLE = "Ungraded: subject on example.com"


@pytest.fixture
async def regraded_scan(db, scan_repo, observation_repo, chain_repo):
    await scan_repo.create_scan(scan_id=SCAN, session_id="s1", target_domain="example.com")
    await observation_repo.bulk_create(
        SCAN,
        [
            {
                "id": "sqli-example.com",
                "title": "SQL Injection",
                "severity": "critical",
                "check_name": "sqli",
                "host": "example.com",
                "grading_state": "graded",
                "grading_tier": "rule",
                "confidence": 0.9,
            },
            {
                "id": "web_header_analysis-example.com-csp",
                "title": "Missing CSP",
                "severity": "medium",
                "check_name": "web_header_analysis",
                "host": "example.com",
                "grading_state": "ungraded",
                "provisional_severity": "medium",
            },
            {
                "id": "web_regrade-example.com-subject",
                "title": PLACEHOLDER_TITLE,
                "severity": "critical",
                "check_name": "web_regrade",
                "host": "example.com",
                "grading_state": "grading_failed",
                "provisional_severity": "critical",
            },
        ],
    )
    # What `regrade --apply` writes for a placeholder graded under a new id.
    await observation_repo.apply_regrade(
        SCAN,
        changed=[],
        added=[
            {
                "id": "web_regrade-example.com-other",
                "title": "Regraded verdict",
                "severity": "high",
                "check_name": "web_regrade",
                "host": "example.com",
                "grading_state": "graded",
                "grading_tier": "rule",
                "confidence": 0.8,
            }
        ],
        superseded={PLACEHOLDER: f"Superseded by offline re-grade: {SUCCESSOR}"},
        successors={PLACEHOLDER: [SUCCESSOR]},
    )
    await chain_repo.bulk_create(
        SCAN,
        [
            {
                "title": "Injection to takeover",
                "severity": "critical",
                "source": "rule-based",
                "observation_ids": [PLACEHOLDER, SQLI],
            }
        ],
    )
    await scan_repo.complete_scan(SCAN, status="complete", observations_count=3)


class TestTechnicalReport:
    async def test_markdown_counts_the_successor_once_and_states_the_placeholder(
        self, regraded_scan
    ):
        content = (await generate_technical_report(SCAN, "md"))["content"]

        # 1 critical (10) + 1 high (5) + 1 medium (2); the placeholder would add 10.
        assert "| Critical | 1 |" in content
        assert "| High | 1 |" in content
        assert "**Risk Score:** 17" in content
        assert "> 1 observation superseded by re-grade." in content
        assert "## Superseded by Re-grade (1)" in content
        [appendix_line] = [line for line in content.splitlines() if PLACEHOLDER_TITLE in line]
        assert f"`{PLACEHOLDER}`" in appendix_line
        assert f"`{SUCCESSOR}`" in appendix_line

    async def test_markdown_never_labels_a_superseded_row_ungraded(self, regraded_scan):
        content = (await generate_technical_report(SCAN, "md"))["content"]

        assert "> 1 observation(s) ungraded" in content  # Missing CSP, and only it
        assert "superseded (provisional severity)" not in content

    async def test_a_chain_renders_through_to_the_successor(self, regraded_scan):
        content = (await generate_technical_report(SCAN, "md"))["content"]

        [line] = [line for line in content.splitlines() if line.startswith("- **Observations:**")]
        assert SUCCESSOR in line
        assert SQLI in line
        assert PLACEHOLDER not in line

    async def test_json_carries_the_count_and_the_successors(self, regraded_scan):
        report = json.loads((await generate_technical_report(SCAN, "json"))["content"])

        assert report["summary"]["total_observations"] == 3
        assert report["summary"]["risk_score"] == 17
        assert len(report["observations"]) == 3
        assert report["ungraded"] == 1
        assert report["superseded"] == 1
        [row] = report["superseded_observations"]
        assert row["id"] == PLACEHOLDER
        assert row["superseded_by"] == [SUCCESSOR]

    async def test_html_states_the_placeholder(self, regraded_scan):
        content = (await generate_technical_report(SCAN, "html"))["content"]

        assert "1 observation superseded by re-grade" in content
        assert "Superseded by Re-grade (1)" in content
        assert SUCCESSOR in content

    async def test_csv_and_sarif_omit_the_superseded_row(self, regraded_scan):
        csv_content = (await generate_technical_report(SCAN, "csv"))["content"]
        sarif = json.loads((await generate_technical_report(SCAN, "sarif"))["content"])

        assert PLACEHOLDER_TITLE not in csv_content
        assert len(sarif["runs"][0]["results"]) == 3
        assert PLACEHOLDER_TITLE not in json.dumps(sarif)


class TestExecutiveAndCompliance:
    async def test_executive_states_the_count_without_an_appendix(self, regraded_scan):
        content = (await generate_executive_report(SCAN, "md"))["content"]

        assert "**Risk Score:** 17" in content
        assert "**Superseded by re-grade (not counted):** 1" in content
        assert "Superseded by Re-grade (" not in content
        assert PLACEHOLDER_TITLE not in content

    async def test_compliance_counts_exclude_the_superseded_row(self, regraded_scan):
        report = json.loads((await generate_compliance_report(SCAN, "json"))["content"])

        assert report["observations"]["total"] == 3
        assert report["observations"]["by_severity"]["critical"] == 1
        assert report["observations"]["superseded_count"] == 1


class TestTargetedExport:
    async def _fingerprint(self, db, observation_id):
        async with db.session() as session:
            result = await session.execute(
                select(ObservationRecord.fingerprint).where(ObservationRecord.id == observation_id)
            )
            return result.scalar_one()

    async def test_a_superseded_row_is_never_the_instance_exported(self, db, regraded_scan):
        placeholder_fp = await self._fingerprint(db, PLACEHOLDER)
        successor_fp = await self._fingerprint(db, SUCCESSOR)

        with pytest.raises(ValueError, match="No observations found"):
            await generate_targeted_export([placeholder_fp], "json", db=db)
        exported = json.loads(
            (await generate_targeted_export([successor_fp], "json", db=db))["content"]
        )
        assert [row["title"] for row in exported["observations"]] == ["Regraded verdict"]
