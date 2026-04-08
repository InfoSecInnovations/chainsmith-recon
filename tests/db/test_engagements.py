"""
Tests for engagement CRUD and scan-engagement linking.
"""

import pytest

from app.db.engine import close_db, init_db
from app.db.repositories import (
    EngagementRepository,
    ScanRepository,
)

pytestmark = pytest.mark.integration

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
