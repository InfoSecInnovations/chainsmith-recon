"""
Tests for engagements, finding status tracking, and scan comparison.
"""

import pytest
from sqlalchemy import func, select

from app.db.engine import close_db, get_session, init_db
from app.db.models import (
    Finding,
    ScanComparison,
)
from app.db.repositories import (
    ComparisonRepository,
    EngagementRepository,
    FindingRepository,
    ScanRepository,
)

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
async def db(tmp_path):
    db_path = tmp_path / "test.db"
    await init_db(backend="sqlite", db_path=db_path)
    yield db_path
    await close_db()


@pytest.fixture
def engagement_repo():
    return EngagementRepository()


@pytest.fixture
def scan_repo():
    return ScanRepository()


@pytest.fixture
def finding_repo():
    return FindingRepository()


@pytest.fixture
def comparison_repo():
    return ComparisonRepository()


@pytest.fixture
async def sample_engagement(db, engagement_repo):
    """Create a sample engagement."""
    return await engagement_repo.create_engagement(
        name="Q1 Pentest",
        target_domain="example.com",
        description="Quarterly pentest",
        client_name="Acme Corp",
    )


# ─── Engagement CRUD Tests ──────────────────────────────────────────────────


class TestEngagementCRUD:
    @pytest.mark.asyncio
    async def test_create_engagement(self, db, engagement_repo):
        eng = await engagement_repo.create_engagement(
            name="Test Engagement",
            target_domain="example.com",
        )
        assert eng["name"] == "Test Engagement"
        assert eng["target_domain"] == "example.com"
        assert eng["status"] == "active"
        assert eng["id"] is not None
        assert len(eng["id"]) == 16

    @pytest.mark.asyncio
    async def test_create_engagement_with_metadata(self, db, engagement_repo):
        eng = await engagement_repo.create_engagement(
            name="Client Pentest",
            target_domain="example.com",
            description="Full assessment",
            client_name="Acme Corp",
        )
        assert eng["description"] == "Full assessment"
        assert eng["client_name"] == "Acme Corp"

    @pytest.mark.asyncio
    async def test_get_engagement(self, sample_engagement, engagement_repo):
        eng = await engagement_repo.get_engagement(sample_engagement["id"])
        assert eng is not None
        assert eng["name"] == "Q1 Pentest"

    @pytest.mark.asyncio
    async def test_get_engagement_not_found(self, db, engagement_repo):
        eng = await engagement_repo.get_engagement("nonexistent")
        assert eng is None

    @pytest.mark.asyncio
    async def test_list_engagements(self, db, engagement_repo):
        await engagement_repo.create_engagement(name="Eng A", target_domain="a.com")
        await engagement_repo.create_engagement(name="Eng B", target_domain="b.com")

        result = await engagement_repo.list_engagements()
        assert result["total"] == 2
        assert len(result["engagements"]) == 2

    @pytest.mark.asyncio
    async def test_list_engagements_filter_status(self, db, engagement_repo):
        await engagement_repo.create_engagement(name="Active", target_domain="a.com")
        eng_b = await engagement_repo.create_engagement(name="Done", target_domain="b.com")
        await engagement_repo.update_engagement(eng_b["id"], status="completed")

        result = await engagement_repo.list_engagements(status="active")
        assert result["total"] == 1
        assert result["engagements"][0]["name"] == "Active"

    @pytest.mark.asyncio
    async def test_update_engagement(self, sample_engagement, engagement_repo):
        updated = await engagement_repo.update_engagement(
            sample_engagement["id"],
            name="Updated Name",
            status="completed",
        )
        assert updated["name"] == "Updated Name"
        assert updated["status"] == "completed"

    @pytest.mark.asyncio
    async def test_update_nonexistent(self, db, engagement_repo):
        result = await engagement_repo.update_engagement("nope", name="X")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_engagement(self, sample_engagement, engagement_repo):
        deleted = await engagement_repo.delete_engagement(sample_engagement["id"])
        assert deleted is True
        eng = await engagement_repo.get_engagement(sample_engagement["id"])
        assert eng is None

    @pytest.mark.asyncio
    async def test_delete_engagement_unlinks_scans(
        self, sample_engagement, engagement_repo, scan_repo
    ):
        """Deleting engagement unlinks scans but doesn't delete them."""
        await scan_repo.create_scan(
            scan_id="scan-linked",
            session_id="s1",
            target_domain="example.com",
            engagement_id=sample_engagement["id"],
        )
        await engagement_repo.delete_engagement(sample_engagement["id"])

        scan = await scan_repo.get_scan("scan-linked")
        assert scan is not None
        assert scan["engagement_id"] is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, db, engagement_repo):
        deleted = await engagement_repo.delete_engagement("nope")
        assert deleted is False

    @pytest.mark.asyncio
    async def test_engagement_dict_shape(self, sample_engagement):
        expected_keys = {
            "id",
            "name",
            "target_domain",
            "description",
            "client_name",
            "created_at",
            "updated_at",
            "status",
        }
        assert expected_keys == set(sample_engagement.keys())


# ─── Scan-Engagement Link Tests ─────────────────────────────────────────────


class TestScanEngagementLink:
    @pytest.mark.asyncio
    async def test_create_scan_with_engagement(self, sample_engagement, scan_repo):
        await scan_repo.create_scan(
            scan_id="scan-eng-001",
            session_id="s1",
            target_domain="example.com",
            engagement_id=sample_engagement["id"],
        )
        scan = await scan_repo.get_scan("scan-eng-001")
        assert scan["engagement_id"] == sample_engagement["id"]

    @pytest.mark.asyncio
    async def test_list_scans_by_engagement(self, sample_engagement, scan_repo):
        await scan_repo.create_scan(
            scan_id="scan-e1",
            session_id="s1",
            target_domain="example.com",
            engagement_id=sample_engagement["id"],
        )
        await scan_repo.create_scan(
            scan_id="scan-e2",
            session_id="s2",
            target_domain="example.com",
            engagement_id=sample_engagement["id"],
        )
        await scan_repo.create_scan(
            scan_id="scan-no-eng",
            session_id="s3",
            target_domain="example.com",
        )

        result = await scan_repo.list_scans(engagement_id=sample_engagement["id"])
        assert result["total"] == 2
        ids = {s["id"] for s in result["scans"]}
        assert ids == {"scan-e1", "scan-e2"}

    @pytest.mark.asyncio
    async def test_scan_dict_includes_engagement_id(self, db, scan_repo):
        await scan_repo.create_scan(
            scan_id="scan-plain",
            session_id="s1",
            target_domain="x.com",
        )
        scan = await scan_repo.get_scan("scan-plain")
        assert "engagement_id" in scan
        assert scan["engagement_id"] is None


# ─── Finding Status Tracking Tests ───────────────────────────────────────────


class TestFindingStatusTracking:
    @pytest.mark.asyncio
    async def test_first_scan_all_new(self, db, scan_repo, finding_repo, comparison_repo):
        """First scan for a target: all findings are 'new'."""
        await scan_repo.create_scan(
            scan_id="first-scan",
            session_id="s1",
            target_domain="fresh.com",
        )
        await finding_repo.bulk_create(
            "first-scan",
            [
                {
                    "title": "Finding A",
                    "severity": "high",
                    "check_name": "check_a",
                    "host": "fresh.com",
                },
                {
                    "title": "Finding B",
                    "severity": "low",
                    "check_name": "check_b",
                    "host": "fresh.com",
                },
            ],
        )
        await scan_repo.complete_scan("first-scan", status="complete", findings_count=2)

        result = await comparison_repo.compute_finding_statuses("first-scan")
        assert result["new"] == 2
        assert result["recurring"] == 0
        assert result["resolved"] == 0
        assert result["regressed"] == 0
        assert result["previous_scan_id"] is None

    @pytest.mark.asyncio
    async def test_second_scan_status_tracking(self, db, scan_repo, finding_repo, comparison_repo):
        """Second scan correctly identifies new, recurring, and resolved."""
        # Scan 1: findings A, B, C
        await scan_repo.create_scan(
            scan_id="scan-v1",
            session_id="s1",
            target_domain="example.com",
        )
        await finding_repo.bulk_create(
            "scan-v1",
            [
                {
                    "id": "f-a",
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "example.com",
                },
                {
                    "id": "f-b",
                    "title": "SQLi",
                    "severity": "critical",
                    "check_name": "sqli",
                    "host": "example.com",
                },
                {
                    "id": "f-c",
                    "title": "Open Port",
                    "severity": "info",
                    "check_name": "port_scan",
                    "host": "example.com",
                },
            ],
        )
        await scan_repo.complete_scan("scan-v1", status="complete", findings_count=3)

        # Compute statuses for scan-v1 BEFORE scan-v2 exists
        result1 = await comparison_repo.compute_finding_statuses("scan-v1")
        assert result1["new"] == 3

        # Scan 2: findings A, D (B and C resolved, D is new)
        await scan_repo.create_scan(
            scan_id="scan-v2",
            session_id="s2",
            target_domain="example.com",
        )
        await finding_repo.bulk_create(
            "scan-v2",
            [
                {
                    "id": "f-a2",
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "example.com",
                },
                {
                    "id": "f-d",
                    "title": "CSRF",
                    "severity": "medium",
                    "check_name": "csrf",
                    "host": "example.com",
                },
            ],
        )
        await scan_repo.complete_scan("scan-v2", status="complete", findings_count=2)

        # Now compute for scan-v2
        result2 = await comparison_repo.compute_finding_statuses("scan-v2")
        assert result2["recurring"] == 1  # XSS still present
        assert result2["resolved"] == 2  # SQLi and Open Port gone
        assert result2["previous_scan_id"] == "scan-v1"
        assert result2["new"] + result2["regressed"] >= 1

    @pytest.mark.asyncio
    async def test_comparison_stored(self, db, scan_repo, finding_repo, comparison_repo):
        """Scan comparison is stored in scan_comparisons table."""
        await scan_repo.create_scan(
            scan_id="cmp-s1",
            session_id="s1",
            target_domain="store.com",
        )
        await finding_repo.bulk_create(
            "cmp-s1",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "store.com"},
            ],
        )
        await scan_repo.complete_scan("cmp-s1", status="complete", findings_count=1)
        await comparison_repo.compute_finding_statuses("cmp-s1")

        await scan_repo.create_scan(
            scan_id="cmp-s2",
            session_id="s2",
            target_domain="store.com",
        )
        await finding_repo.bulk_create(
            "cmp-s2",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "store.com"},
            ],
        )
        await scan_repo.complete_scan("cmp-s2", status="complete", findings_count=1)
        await comparison_repo.compute_finding_statuses("cmp-s2")

        async with get_session() as session:
            result = await session.execute(select(func.count()).select_from(ScanComparison))
            assert result.scalar() == 1

    @pytest.mark.asyncio
    async def test_finding_history(self, db, scan_repo, finding_repo, comparison_repo):
        """Finding history tracks status across scans."""
        await scan_repo.create_scan(
            scan_id="hist-s1",
            session_id="s1",
            target_domain="hist.com",
        )
        await finding_repo.bulk_create(
            "hist-s1",
            [
                {
                    "id": "h-a",
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "hist.com",
                },
            ],
        )
        await scan_repo.complete_scan("hist-s1", status="complete", findings_count=1)
        await comparison_repo.compute_finding_statuses("hist-s1")

        await scan_repo.create_scan(
            scan_id="hist-s2",
            session_id="s2",
            target_domain="hist.com",
        )
        await finding_repo.bulk_create(
            "hist-s2",
            [
                {
                    "id": "h-a2",
                    "title": "XSS",
                    "severity": "high",
                    "check_name": "xss",
                    "host": "hist.com",
                },
            ],
        )
        await scan_repo.complete_scan("hist-s2", status="complete", findings_count=1)
        await comparison_repo.compute_finding_statuses("hist-s2")

        # Get the XSS fingerprint
        async with get_session() as session:
            result = await session.execute(select(Finding.fingerprint).where(Finding.id == "h-a"))
            xss_fp = result.scalar_one()

        history = await comparison_repo.get_finding_history(xss_fp)
        assert len(history) >= 2
        statuses = [h["status"] for h in history]
        assert "new" in statuses
        assert "recurring" in statuses


# ─── Scan Comparison Tests ───────────────────────────────────────────────────


class TestScanComparison:
    @pytest.fixture
    async def comparable_scans(self, db, scan_repo, finding_repo):
        """Two scans with known fingerprint overlap."""
        await scan_repo.create_scan(
            scan_id="cmp-a",
            session_id="s1",
            target_domain="example.com",
        )
        await finding_repo.bulk_create(
            "cmp-a",
            [
                {
                    "id": "ca-1",
                    "title": "F1",
                    "severity": "high",
                    "check_name": "c1",
                    "host": "example.com",
                },
                {
                    "id": "ca-2",
                    "title": "F2",
                    "severity": "medium",
                    "check_name": "c2",
                    "host": "example.com",
                },
                {
                    "id": "ca-3",
                    "title": "F3",
                    "severity": "low",
                    "check_name": "c3",
                    "host": "example.com",
                },
            ],
        )
        await scan_repo.complete_scan("cmp-a", status="complete", findings_count=3)

        await scan_repo.create_scan(
            scan_id="cmp-b",
            session_id="s2",
            target_domain="example.com",
        )
        await finding_repo.bulk_create(
            "cmp-b",
            [
                {
                    "id": "cb-1",
                    "title": "F1",
                    "severity": "high",
                    "check_name": "c1",
                    "host": "example.com",
                },  # Same as ca-1
                {
                    "id": "cb-4",
                    "title": "F4",
                    "severity": "critical",
                    "check_name": "c4",
                    "host": "example.com",
                },  # New
            ],
        )
        await scan_repo.complete_scan("cmp-b", status="complete", findings_count=2)

        return {"a": "cmp-a", "b": "cmp-b"}

    @pytest.mark.asyncio
    async def test_compare_scans(self, comparable_scans, comparison_repo):
        result = await comparison_repo.compare_scans("cmp-a", "cmp-b")
        assert result["scan_a_id"] == "cmp-a"
        assert result["scan_b_id"] == "cmp-b"
        assert result["recurring_count"] == 1  # F1
        assert result["new_count"] == 1  # F4
        assert result["resolved_count"] == 2  # F2 and F3

    @pytest.mark.asyncio
    async def test_compare_new_findings_detail(self, comparable_scans, comparison_repo):
        result = await comparison_repo.compare_scans("cmp-a", "cmp-b")
        new_titles = {f["title"] for f in result["new_findings"]}
        assert "F4" in new_titles

    @pytest.mark.asyncio
    async def test_compare_resolved_findings_detail(self, comparable_scans, comparison_repo):
        result = await comparison_repo.compare_scans("cmp-a", "cmp-b")
        resolved_titles = {f["title"] for f in result["resolved_findings"]}
        assert "F2" in resolved_titles
        assert "F3" in resolved_titles

    @pytest.mark.asyncio
    async def test_compare_identical_scans(self, db, scan_repo, finding_repo, comparison_repo):
        """Comparing a scan with itself: all recurring, no new/resolved."""
        await scan_repo.create_scan(
            scan_id="same-a",
            session_id="s1",
            target_domain="x.com",
        )
        await finding_repo.bulk_create(
            "same-a",
            [
                {"title": "F1", "severity": "high", "check_name": "c1", "host": "x.com"},
            ],
        )

        result = await comparison_repo.compare_scans("same-a", "same-a")
        assert result["new_count"] == 0
        assert result["resolved_count"] == 0
        assert result["recurring_count"] == 1

    @pytest.mark.asyncio
    async def test_finding_history_empty(self, db, comparison_repo):
        """No history for unknown fingerprint."""
        history = await comparison_repo.get_finding_history("nonexistent")
        assert history == []
