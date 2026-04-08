"""Tests for SARIF output format for all 5 report types."""

import json

import pytest

from app.db.models import ObservationRecord
from app.reports import (
    generate_compliance_report,
    generate_delta_report,
    generate_executive_report,
    generate_technical_report,
    generate_trend_report,
)

from .conftest import _create_populated_scan

pytestmark = pytest.mark.integration


class TestTechnicalReportSARIF:
    @pytest.mark.asyncio
    async def test_sarif_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_technical_report("sarif-scan", "sarif")

        assert result["format"] == "sarif"
        assert result["filename"].endswith(".sarif.json")

        sarif = json.loads(result["content"])
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    @pytest.mark.asyncio
    async def test_sarif_results(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        results = sarif["runs"][0]["results"]
        assert len(results) == 4

        # Check severity mapping
        levels = [r["level"] for r in results]
        assert "error" in levels  # critical and high map to error
        assert "warning" in levels  # medium maps to warning
        assert "note" in levels  # info maps to note

    @pytest.mark.asyncio
    async def test_sarif_rules(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "xss_reflected" in rule_ids
        assert "sqli" in rule_ids
        assert "header_analysis" in rule_ids
        assert "server_header" in rule_ids

    @pytest.mark.asyncio
    async def test_sarif_tool_info(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Chainsmith Recon"
        assert driver["version"] == "1.3.0"

    @pytest.mark.asyncio
    async def test_sarif_locations(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        # XSS observation should have a location with target_url
        results = sarif["runs"][0]["results"]
        xss_result = next(r for r in results if r["ruleId"] == "xss_reflected")
        assert "locations" in xss_result
        assert (
            xss_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "http://example.com/search"
        )

    @pytest.mark.asyncio
    async def test_sarif_fingerprints(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        # All observations should have fingerprints
        for r in sarif["runs"][0]["results"]:
            assert "fingerprints" in r
            assert "chainsmith/v1" in r["fingerprints"]

    @pytest.mark.asyncio
    async def test_sarif_evidence_attachments(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        # XSS observation has evidence
        results = sarif["runs"][0]["results"]
        xss_result = next(r for r in results if r["ruleId"] == "xss_reflected")
        assert "attachments" in xss_result
        assert xss_result["attachments"][0]["contents"]["text"] == "<script>alert(1)</script>"

    @pytest.mark.asyncio
    async def test_sarif_invocation_props(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        invocation = sarif["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True
        props = invocation["properties"]
        assert props["reportType"] == "technical"
        assert props["riskScore"] == 17
        assert props["target"] == "example.com"
        assert props["chainCount"] == 1

    @pytest.mark.asyncio
    async def test_sarif_help_uri(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_technical_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        xss_rule = next(r for r in rules if r["id"] == "xss_reflected")
        assert xss_rule["helpUri"] == "https://owasp.org/xss"


class TestDeltaReportSARIF:
    @pytest.fixture
    async def two_scans(self, db, scan_repo, observation_repo):
        await scan_repo.create_scan(scan_id="ds-a", session_id="s1", target_domain="sarif.com")
        await observation_repo.bulk_create(
            "ds-a",
            [
                {
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "sarif.com",
                    "suite": "web",
                },
                {
                    "title": "SQLi",
                    "severity": "critical",
                    "check_name": "sqli",
                    "host": "sarif.com",
                    "suite": "web",
                },
            ],
        )
        await scan_repo.complete_scan("ds-a", status="complete", observations_count=2)

        await scan_repo.create_scan(scan_id="ds-b", session_id="s2", target_domain="sarif.com")
        await observation_repo.bulk_create(
            "ds-b",
            [
                {
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "sarif.com",
                    "suite": "web",
                },
                {
                    "title": "CSRF",
                    "severity": "medium",
                    "check_name": "csrf",
                    "host": "sarif.com",
                    "suite": "web",
                },
            ],
        )
        await scan_repo.complete_scan("ds-b", status="complete", observations_count=2)

    @pytest.mark.asyncio
    async def test_sarif_structure(self, two_scans):
        result = await generate_delta_report("ds-a", "ds-b", "sarif")
        assert result["format"] == "sarif"
        sarif = json.loads(result["content"])
        assert sarif["version"] == "2.1.0"

    @pytest.mark.asyncio
    async def test_sarif_contains_new_observations_only(self, two_scans):
        result = await generate_delta_report("ds-a", "ds-b", "sarif")
        sarif = json.loads(result["content"])
        results = sarif["runs"][0]["results"]
        # Only new observations (CSRF) should appear
        assert len(results) == 1
        assert "CSRF" in results[0]["message"]["text"]

    @pytest.mark.asyncio
    async def test_sarif_invocation_metadata(self, two_scans):
        result = await generate_delta_report("ds-a", "ds-b", "sarif")
        sarif = json.loads(result["content"])
        props = sarif["runs"][0]["invocations"][0]["properties"]
        assert props["reportType"] == "delta"
        assert props["scanA"] == "ds-a"
        assert props["scanB"] == "ds-b"


class TestExecutiveReportSARIF:
    @pytest.mark.asyncio
    async def test_sarif_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_executive_report("sarif-scan", "sarif")
        assert result["format"] == "sarif"
        sarif = json.loads(result["content"])
        assert sarif["version"] == "2.1.0"
        # Executive shows top 5 observations
        assert len(sarif["runs"][0]["results"]) <= 5

    @pytest.mark.asyncio
    async def test_sarif_invocation_metadata(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_executive_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])
        props = sarif["runs"][0]["invocations"][0]["properties"]
        assert props["reportType"] == "executive"
        assert props["riskScore"] == 17
        assert props["activeObservations"] == 4


class TestComplianceReportSARIF:
    @pytest.mark.asyncio
    async def test_sarif_structure(
        self, db, scan_repo, observation_repo, chain_repo, check_log_repo
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )
        result = await generate_compliance_report("sarif-scan", "sarif")
        assert result["format"] == "sarif"
        sarif = json.loads(result["content"])
        assert sarif["version"] == "2.1.0"

    @pytest.mark.asyncio
    async def test_sarif_with_overrides(
        self,
        db,
        scan_repo,
        observation_repo,
        chain_repo,
        check_log_repo,
        override_repo,
    ):
        await _create_populated_scan(
            scan_repo, observation_repo, chain_repo, check_log_repo, scan_id="sarif-scan"
        )

        from sqlalchemy import select

        async with db.session() as session:
            result = await session.execute(
                select(ObservationRecord.fingerprint).where(
                    ObservationRecord.title == "Missing CSP"
                )
            )
            fp = result.scalar_one()

        await override_repo.set_override(fp, "accepted", reason="Known risk")

        result = await generate_compliance_report("sarif-scan", "sarif")
        sarif = json.loads(result["content"])
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["suppressions"][0]["status"] == "accepted"
        assert results[0]["suppressions"][0]["justification"] == "Known risk"


class TestTrendReportSARIF:
    @pytest.fixture
    async def target_scans(self, db, scan_repo, observation_repo, chain_repo, check_log_repo):
        await _create_populated_scan(
            scan_repo,
            observation_repo,
            chain_repo,
            check_log_repo,
            scan_id="ts-1",
            target="sarif-trend.com",
        )

    @pytest.mark.asyncio
    async def test_sarif_structure(self, target_scans):
        result = await generate_trend_report("sarif", target="sarif-trend.com")
        assert result["format"] == "sarif"
        sarif = json.loads(result["content"])
        assert sarif["version"] == "2.1.0"

    @pytest.mark.asyncio
    async def test_sarif_data_points(self, target_scans):
        result = await generate_trend_report("sarif", target="sarif-trend.com")
        sarif = json.loads(result["content"])
        results = sarif["runs"][0]["results"]
        assert len(results) >= 1
        # Each result represents a data point
        assert results[0]["ruleId"] == "trend_data_point"
        props = results[0]["properties"]
        assert "riskScore" in props
        assert "total" in props
