"""
app/db/repositories.py - Async data access layer.

Repository pattern for persisting and querying scan results.
Write methods (Phase 1) persist scan data at lifecycle points.
Read methods (Phase 2) serve historical data to API endpoints.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, func, select

from app.db.engine import Database, get_session
from app.db.models import (
    AdjudicationResult,
    AdvisorRecommendation,
    Chain,
    ChatMessage,
    CheckLog,
    Engagement,
    ObservationOverride,
    ObservationRecord,
    ObservationStatusHistory,
    Scan,
    ScanComparison,
    TriageActionRecord,
    TriagePlanRecord,
)

logger = logging.getLogger(__name__)


class _RepositoryBase:
    """Shared base: optional ``Database`` injection, falls back to global."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    def _session(self):
        """Return a new async session from the injected or global DB."""
        if self._db is not None:
            return self._db.session()
        return get_session()


def _generate_fingerprint(check_name: str, host: str, title: str, evidence: str = "") -> str:
    """
    Generate a stable fingerprint for deduplicating observations across scans.

    The fingerprint is a hash of (check_name, host, title, key_evidence).
    Strips timestamps and request IDs from evidence before hashing.
    """
    normalized = f"{check_name}|{host or ''}|{title}|{evidence or ''}"
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


class ScanRepository(_RepositoryBase):
    """Persist scan metadata."""

    async def create_scan(
        self,
        scan_id: str,
        session_id: str,
        target_domain: str,
        settings: dict | None = None,
        scope: dict | None = None,
        profile_name: str | None = None,
        scenario_name: str | None = None,
        engagement_id: str | None = None,
    ) -> str:
        """Insert a new scan record (status=running). Returns the scan ID."""
        scan = Scan(
            id=scan_id,
            session_id=session_id,
            target_domain=target_domain,
            status="running",
            started_at=datetime.now(UTC),
            settings=settings,
            scope=scope,
            profile_name=profile_name,
            scenario_name=scenario_name,
            engagement_id=engagement_id,
        )
        async with self._session() as session:
            session.add(scan)
            await session.commit()
        logger.info(f"Scan {scan_id} persisted (status=running)")
        return scan_id

    async def complete_scan(
        self,
        scan_id: str,
        status: str = "complete",
        checks_total: int = 0,
        checks_completed: int = 0,
        checks_failed: int = 0,
        observations_count: int = 0,
        duration_ms: int | None = None,
        error_message: str | None = None,
    ) -> None:
        """Mark a scan as complete/error and record summary stats."""
        async with self._session() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan is None:
                logger.warning(f"Scan {scan_id} not found in DB for completion update")
                return
            scan.status = status
            scan.completed_at = datetime.now(UTC)
            scan.checks_total = checks_total
            scan.checks_completed = checks_completed
            scan.checks_failed = checks_failed
            scan.observations_count = observations_count
            scan.duration_ms = duration_ms
            scan.error_message = error_message
            await session.commit()
        logger.info(f"Scan {scan_id} updated (status={status}, observations={observations_count})")

    async def update_scan_status(
        self,
        scan_id: str,
        **fields: str | None,
    ) -> None:
        """Update specific status fields on a scan record.

        Accepts any combination of: adjudication_status, adjudication_error,
        chain_status, chain_error, chain_llm_analysis.
        """
        allowed = {
            "adjudication_status",
            "adjudication_error",
            "chain_status",
            "chain_error",
            "chain_llm_analysis",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return

        async with self._session() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan is None:
                logger.warning(f"Scan {scan_id} not found for status update")
                return
            for key, value in updates.items():
                setattr(scan, key, value)
            await session.commit()
        logger.info(f"Scan {scan_id} status updated: {list(updates.keys())}")

    async def get_most_recent_scan_id(self) -> str | None:
        """Get the ID of the most recent completed scan, or None."""
        query = (
            select(Scan.id)
            .where(Scan.status == "complete")
            .order_by(Scan.started_at.desc())
            .limit(1)
        )
        async with self._session() as session:
            result = await session.execute(query)
            row = result.scalar_one_or_none()
        return row

    async def get_scan(self, scan_id: str) -> dict | None:
        """Get a scan by ID. Returns dict or None."""
        async with self._session() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan is None:
                return None
            return _scan_to_dict(scan)

    async def list_scans(
        self,
        target: str | None = None,
        status: str | None = None,
        engagement_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """List scans with optional filters. Returns {total, scans}."""
        query = select(Scan)
        count_query = select(func.count()).select_from(Scan)

        if target:
            query = query.where(Scan.target_domain == target)
            count_query = count_query.where(Scan.target_domain == target)
        if status:
            query = query.where(Scan.status == status)
            count_query = count_query.where(Scan.status == status)
        if engagement_id:
            query = query.where(Scan.engagement_id == engagement_id)
            count_query = count_query.where(Scan.engagement_id == engagement_id)

        query = query.order_by(Scan.started_at.desc()).limit(limit).offset(offset)

        async with self._session() as session:
            total_result = await session.execute(count_query)
            total = total_result.scalar()
            result = await session.execute(query)
            scans = [_scan_to_dict(s) for s in result.scalars().all()]

        return {"total": total, "scans": scans}

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all related data. Returns True if scan existed."""
        async with self._session() as session:
            # Check existence
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan is None:
                return False

            # Delete related data first, then the scan
            await session.execute(
                delete(ObservationStatusHistory).where(ObservationStatusHistory.scan_id == scan_id)
            )
            await session.execute(
                delete(ScanComparison).where(
                    (ScanComparison.scan_a_id == scan_id) | (ScanComparison.scan_b_id == scan_id)
                )
            )
            await session.execute(
                delete(AdjudicationResult).where(AdjudicationResult.scan_id == scan_id)
            )
            await session.execute(
                delete(AdvisorRecommendation).where(AdvisorRecommendation.scan_id == scan_id)
            )
            await session.execute(delete(CheckLog).where(CheckLog.scan_id == scan_id))
            await session.execute(delete(Chain).where(Chain.scan_id == scan_id))
            await session.execute(
                delete(ObservationRecord).where(ObservationRecord.scan_id == scan_id)
            )
            await session.execute(delete(Scan).where(Scan.id == scan_id))
            await session.commit()

        logger.info(f"Deleted scan {scan_id} and all related data")
        return True


def _scan_to_dict(scan: Scan) -> dict:
    """Convert a Scan ORM object to a JSON-safe dict."""
    return {
        "id": scan.id,
        "engagement_id": scan.engagement_id,
        "session_id": scan.session_id,
        "target_domain": scan.target_domain,
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration_ms": scan.duration_ms,
        "checks_total": scan.checks_total,
        "checks_completed": scan.checks_completed,
        "checks_failed": scan.checks_failed,
        "observations_count": scan.observations_count,
        "scope": scan.scope,
        "settings": scan.settings,
        "profile_name": scan.profile_name,
        "scenario_name": scan.scenario_name,
        "error_message": scan.error_message,
        "adjudication_status": scan.adjudication_status or "idle",
        "adjudication_error": scan.adjudication_error,
        "chain_status": scan.chain_status or "idle",
        "chain_error": scan.chain_error,
        "chain_llm_analysis": scan.chain_llm_analysis,
    }


class ObservationRepository(_RepositoryBase):
    """Persist scan observations."""

    async def bulk_create(self, scan_id: str, observations: list[dict]) -> int:
        """
        Insert observations from a completed scan. Returns count inserted.

        Each observation dict is expected to have the shape produced by checks
        (title, description, severity, check_name, etc.).
        """
        if not observations:
            return 0

        rows = []
        for f in observations:
            observation_id = f.get("id") or uuid.uuid4().hex[:12]
            host = f.get("host") or f.get("target_url", "")
            fingerprint = _generate_fingerprint(
                check_name=f.get("check_name", f.get("check", "")),
                host=host,
                title=f.get("title", ""),
                evidence=f.get("evidence", ""),
            )
            rows.append(
                ObservationRecord(
                    id=observation_id,
                    scan_id=scan_id,
                    title=f.get("title", "Untitled"),
                    description=f.get("description"),
                    severity=f.get("severity", "info"),
                    check_name=f.get("check_name", f.get("check", "unknown")),
                    suite=f.get("suite"),
                    target_url=f.get("target_url") or f.get("url"),
                    host=host,
                    evidence=f.get("evidence"),
                    raw_data=f.get("raw_data") or f.get("raw"),
                    references=f.get("references"),
                    verification_status=f.get("verification_status", "pending"),
                    confidence=f.get("confidence"),
                    fingerprint=fingerprint,
                )
            )

        async with self._session() as session:
            session.add_all(rows)
            await session.commit()

        logger.info(f"Persisted {len(rows)} observations for scan {scan_id}")
        return len(rows)

    async def get_observations(
        self,
        scan_id: str,
        severity: str | None = None,
        host: str | None = None,
    ) -> list[dict]:
        """Get observations for a scan with optional filters.

        Severity overrides from user customizations are applied before
        filtering, so the severity parameter filters on effective severity.
        """
        query = select(ObservationRecord).where(ObservationRecord.scan_id == scan_id)
        # Host filter can still be applied at query level
        if host:
            query = query.where(ObservationRecord.host == host)

        async with self._session() as session:
            result = await session.execute(query)
            observations = [_observation_to_dict(f) for f in result.scalars().all()]

        # Apply scan-specific severity overrides from user customizations
        from app.customizations import apply_scan_overrides

        observations = apply_scan_overrides(observations, scan_id)

        # Filter by severity AFTER overrides so filtering sees effective severity
        if severity:
            observations = [f for f in observations if f["severity"] == severity]

        return observations

    async def get_observations_by_host(self, scan_id: str) -> list[dict]:
        """Get observations for a scan grouped by host.

        Severity overrides from user customizations are applied.
        """
        async with self._session() as session:
            result = await session.execute(
                select(ObservationRecord).where(ObservationRecord.scan_id == scan_id)
            )
            observation_dicts = [_observation_to_dict(f) for f in result.scalars().all()]

        # Apply scan-specific severity overrides
        from app.customizations import apply_scan_overrides

        observation_dicts = apply_scan_overrides(observation_dicts, scan_id)

        hosts: dict[str, list[dict]] = {}
        for f in observation_dicts:
            host = f.get("host") or "unknown"
            if host not in hosts:
                hosts[host] = []
            hosts[host].append(f)

        return [{"name": host, "observations": flist} for host, flist in hosts.items()]


def _observation_to_dict(f: ObservationRecord) -> dict:
    """Convert an ObservationRecord ORM object to a JSON-safe dict.

    Override fields (original_severity, severity_override_reason, override_source)
    default to None and are populated by apply_scan_overrides() at read time.
    """
    return {
        "id": f.id,
        "scan_id": f.scan_id,
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "check_name": f.check_name,
        "suite": f.suite,
        "target_url": f.target_url,
        "host": f.host,
        "evidence": f.evidence,
        "raw_data": f.raw_data,
        "references": f.references,
        "verification_status": f.verification_status,
        "confidence": f.confidence,
        "fingerprint": f.fingerprint,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "original_severity": None,
        "severity_override_reason": None,
        "override_source": None,
    }


class ChainRepository(_RepositoryBase):
    """Persist attack chains."""

    async def bulk_create(self, scan_id: str, chains: list[dict]) -> int:
        """Insert chains from a completed scan. Returns count inserted."""
        if not chains:
            return 0

        rows = []
        for c in chains:
            chain_id = c.get("id") or uuid.uuid4().hex[:12]
            rows.append(
                Chain(
                    id=chain_id,
                    scan_id=scan_id,
                    title=c.get("title", "Untitled Chain"),
                    description=c.get("description"),
                    severity=c.get("severity", "info"),
                    source=c.get("source", "rule-based"),
                    observation_ids=c.get("observation_ids") or c.get("observations"),
                )
            )

        async with self._session() as session:
            session.add_all(rows)
            await session.commit()

        logger.info(f"Persisted {len(rows)} chains for scan {scan_id}")
        return len(rows)

    async def get_chains(self, scan_id: str) -> list[dict]:
        """Get chains for a scan."""
        async with self._session() as session:
            result = await session.execute(select(Chain).where(Chain.scan_id == scan_id))
            return [_chain_to_dict(c) for c in result.scalars().all()]


def _chain_to_dict(c: Chain) -> dict:
    """Convert a Chain ORM object to a JSON-safe dict."""
    return {
        "id": c.id,
        "scan_id": c.scan_id,
        "title": c.title,
        "description": c.description,
        "severity": c.severity,
        "source": c.source,
        "observation_ids": c.observation_ids,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


class CheckLogRepository(_RepositoryBase):
    """Persist check execution log entries."""

    async def bulk_create(self, scan_id: str, log_entries: list[dict]) -> int:
        """Insert check log entries. Returns count inserted."""
        if not log_entries:
            return 0

        rows = []
        for entry in log_entries:
            rows.append(
                CheckLog(
                    scan_id=scan_id,
                    check_name=entry.get("check", "unknown"),
                    suite=entry.get("suite"),
                    event=entry.get("event", "unknown"),
                    observations_count=entry.get("observations", 0),
                    duration_ms=entry.get("duration_ms"),
                    error_message=entry.get("error_message"),
                )
            )

        async with self._session() as session:
            session.add_all(rows)
            await session.commit()

        logger.info(f"Persisted {len(rows)} check log entries for scan {scan_id}")
        return len(rows)

    async def get_log(self, scan_id: str) -> list[dict]:
        """Get check log entries for a scan."""
        async with self._session() as session:
            result = await session.execute(
                select(CheckLog).where(CheckLog.scan_id == scan_id).order_by(CheckLog.id)
            )
            return [_check_log_to_dict(entry) for entry in result.scalars().all()]


def _check_log_to_dict(entry: CheckLog) -> dict:
    """Convert a CheckLog ORM object to a JSON-safe dict."""
    return {
        "check": entry.check_name,
        "suite": entry.suite,
        "event": entry.event,
        "observations": entry.observations_count,
        "duration_ms": entry.duration_ms,
        "error_message": entry.error_message,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
    }


class EngagementRepository(_RepositoryBase):
    """Persist and query engagements."""

    async def create_engagement(
        self,
        name: str,
        target_domain: str,
        description: str | None = None,
        client_name: str | None = None,
    ) -> dict:
        """Create a new engagement. Returns the engagement dict."""
        engagement_id = uuid.uuid4().hex[:16]
        now = datetime.now(UTC)
        engagement = Engagement(
            id=engagement_id,
            name=name,
            target_domain=target_domain,
            description=description,
            client_name=client_name,
            created_at=now,
            updated_at=now,
        )
        async with self._session() as session:
            session.add(engagement)
            await session.commit()
        logger.info(f"Created engagement {engagement_id}: {name}")
        return _engagement_to_dict(engagement)

    async def get_engagement(self, engagement_id: str) -> dict | None:
        """Get an engagement by ID."""
        async with self._session() as session:
            result = await session.execute(select(Engagement).where(Engagement.id == engagement_id))
            eng = result.scalar_one_or_none()
            return _engagement_to_dict(eng) if eng else None

    async def list_engagements(
        self,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """List engagements. Returns {total, engagements}."""
        query = select(Engagement)
        count_query = select(func.count()).select_from(Engagement)

        if status:
            query = query.where(Engagement.status == status)
            count_query = count_query.where(Engagement.status == status)

        query = query.order_by(Engagement.updated_at.desc()).limit(limit).offset(offset)

        async with self._session() as session:
            total_result = await session.execute(count_query)
            total = total_result.scalar()
            result = await session.execute(query)
            engagements = [_engagement_to_dict(e) for e in result.scalars().all()]

        return {"total": total, "engagements": engagements}

    async def update_engagement(
        self,
        engagement_id: str,
        name: str | None = None,
        description: str | None = None,
        client_name: str | None = None,
        status: str | None = None,
    ) -> dict | None:
        """Update an engagement. Returns updated dict or None if not found."""
        async with self._session() as session:
            result = await session.execute(select(Engagement).where(Engagement.id == engagement_id))
            eng = result.scalar_one_or_none()
            if eng is None:
                return None
            if name is not None:
                eng.name = name
            if description is not None:
                eng.description = description
            if client_name is not None:
                eng.client_name = client_name
            if status is not None:
                eng.status = status
            eng.updated_at = datetime.now(UTC)
            await session.commit()
            return _engagement_to_dict(eng)

    async def delete_engagement(self, engagement_id: str) -> bool:
        """Delete an engagement and unlink its scans. Returns True if existed."""
        async with self._session() as session:
            result = await session.execute(select(Engagement).where(Engagement.id == engagement_id))
            eng = result.scalar_one_or_none()
            if eng is None:
                return False

            # Unlink scans (don't delete them — they're still valid historical data)
            scans_result = await session.execute(
                select(Scan).where(Scan.engagement_id == engagement_id)
            )
            for scan in scans_result.scalars().all():
                scan.engagement_id = None

            await session.execute(delete(Engagement).where(Engagement.id == engagement_id))
            await session.commit()
        logger.info(f"Deleted engagement {engagement_id}")
        return True


def _engagement_to_dict(eng: Engagement) -> dict:
    """Convert an Engagement ORM object to a JSON-safe dict."""
    return {
        "id": eng.id,
        "name": eng.name,
        "target_domain": eng.target_domain,
        "description": eng.description,
        "client_name": eng.client_name,
        "created_at": eng.created_at.isoformat() if eng.created_at else None,
        "updated_at": eng.updated_at.isoformat() if eng.updated_at else None,
        "status": eng.status,
    }


class ComparisonRepository(_RepositoryBase):
    """Compute and store observation status tracking and scan comparisons."""

    async def compute_observation_statuses(self, scan_id: str) -> dict:
        """
        Compare the current scan's fingerprints against the previous scan
        for the same target (or engagement). Writes ObservationStatusHistory
        entries and a ScanComparison record.

        Returns {new, recurring, resolved, regressed, previous_scan_id}.
        """
        async with self._session() as session:
            # Get current scan
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            current_scan = result.scalar_one_or_none()
            if current_scan is None:
                return {"new": 0, "recurring": 0, "resolved": 0, "regressed": 0}

            # Find previous scan for the same target (or engagement)
            prev_query = (
                select(Scan)
                .where(Scan.target_domain == current_scan.target_domain)
                .where(Scan.id != scan_id)
                .where(Scan.status == "complete")
            )
            if current_scan.engagement_id:
                prev_query = prev_query.where(Scan.engagement_id == current_scan.engagement_id)
            prev_query = prev_query.order_by(Scan.started_at.desc()).limit(1)

            result = await session.execute(prev_query)
            previous_scan = result.scalar_one_or_none()

            # Get all current fingerprints (used for first-scan path)
            result = await session.execute(
                select(ObservationRecord.fingerprint).where(ObservationRecord.scan_id == scan_id)
            )
            all_current_fps = {row[0] for row in result.all() if row[0]}

            if previous_scan is None:
                # First scan — all observations are new
                for fp in all_current_fps:
                    session.add(
                        ObservationStatusHistory(
                            fingerprint=fp,
                            scan_id=scan_id,
                            status="new",
                            first_seen_scan=scan_id,
                            last_seen_scan=scan_id,
                        )
                    )
                await session.commit()
                return {
                    "new": len(all_current_fps),
                    "recurring": 0,
                    "resolved": 0,
                    "regressed": 0,
                    "previous_scan_id": None,
                }

            # -- Check-aware comparison --
            # Get checks that actually executed (completed or failed, not skipped)
            # in both scans. Only compare observations from this common set.
            executed_events = ("completed", "failed")

            result = await session.execute(
                select(CheckLog.check_name)
                .where(CheckLog.scan_id == scan_id)
                .where(CheckLog.event.in_(executed_events))
            )
            current_checks = {row[0] for row in result.all()}

            result = await session.execute(
                select(CheckLog.check_name)
                .where(CheckLog.scan_id == previous_scan.id)
                .where(CheckLog.event.in_(executed_events))
            )
            previous_checks = {row[0] for row in result.all()}

            common_checks = current_checks & previous_checks

            # Get fingerprints only for observations whose check ran in both scans
            if common_checks:
                result = await session.execute(
                    select(ObservationRecord.fingerprint)
                    .where(ObservationRecord.scan_id == scan_id)
                    .where(ObservationRecord.check_name.in_(common_checks))
                )
                current_fps = {row[0] for row in result.all() if row[0]}

                result = await session.execute(
                    select(ObservationRecord.fingerprint)
                    .where(ObservationRecord.scan_id == previous_scan.id)
                    .where(ObservationRecord.check_name.in_(common_checks))
                )
                previous_fps = {row[0] for row in result.all() if row[0]}
            else:
                # No common checks (edge case) — fall back to all fingerprints
                current_fps = all_current_fps
                result = await session.execute(
                    select(ObservationRecord.fingerprint).where(
                        ObservationRecord.scan_id == previous_scan.id
                    )
                )
                previous_fps = {row[0] for row in result.all() if row[0]}

            # Observations from checks that only ran in current scan are "new"
            # (we can't compare them — no prior baseline)
            current_only_checks = current_checks - previous_checks
            if current_only_checks:
                result = await session.execute(
                    select(ObservationRecord.fingerprint)
                    .where(ObservationRecord.scan_id == scan_id)
                    .where(ObservationRecord.check_name.in_(current_only_checks))
                )
                current_only_fps = {row[0] for row in result.all() if row[0]}
            else:
                current_only_fps = set()

            # Check for regressed: was resolved in a prior comparison but is back now
            result = await session.execute(
                select(ObservationStatusHistory.fingerprint)
                .where(ObservationStatusHistory.status == "resolved")
                .where(ObservationStatusHistory.fingerprint.in_(current_fps | current_only_fps))
            )
            previously_resolved = {row[0] for row in result.all()}

            new_fps = (current_fps - previous_fps - previously_resolved) | (
                current_only_fps - previously_resolved
            )
            recurring_fps = current_fps & previous_fps
            resolved_fps = previous_fps - current_fps
            regressed_fps = (current_fps | current_only_fps) & previously_resolved

            # Write status history entries
            for fp in new_fps:
                session.add(
                    ObservationStatusHistory(
                        fingerprint=fp,
                        scan_id=scan_id,
                        status="new",
                        first_seen_scan=scan_id,
                        last_seen_scan=scan_id,
                    )
                )
            for fp in recurring_fps:
                session.add(
                    ObservationStatusHistory(
                        fingerprint=fp,
                        scan_id=scan_id,
                        status="recurring",
                        last_seen_scan=scan_id,
                    )
                )
            for fp in resolved_fps:
                session.add(
                    ObservationStatusHistory(
                        fingerprint=fp,
                        scan_id=scan_id,
                        status="resolved",
                        last_seen_scan=previous_scan.id,
                    )
                )
            for fp in regressed_fps:
                session.add(
                    ObservationStatusHistory(
                        fingerprint=fp,
                        scan_id=scan_id,
                        status="regressed",
                        last_seen_scan=scan_id,
                    )
                )

            # Store precomputed comparison
            comparison = ScanComparison(
                scan_a_id=previous_scan.id,
                scan_b_id=scan_id,
                new_observations=len(new_fps) + len(regressed_fps),
                resolved=len(resolved_fps),
                recurring=len(recurring_fps),
                regressed=len(regressed_fps),
            )
            session.add(comparison)
            await session.commit()

        stats = {
            "new": len(new_fps),
            "recurring": len(recurring_fps),
            "resolved": len(resolved_fps),
            "regressed": len(regressed_fps),
            "previous_scan_id": previous_scan.id,
        }
        logger.info(f"Observation statuses for scan {scan_id}: {stats}")
        return stats

    async def compare_scans(self, scan_a_id: str, scan_b_id: str) -> dict:
        """
        Compare two scans by fingerprint. Returns comparison stats and
        observation lists. Checks for a cached comparison first.
        """
        async with self._session() as session:
            # Check cache
            result = await session.execute(
                select(ScanComparison).where(
                    ScanComparison.scan_a_id == scan_a_id,
                    ScanComparison.scan_b_id == scan_b_id,
                )
            )
            result.scalar_one_or_none()

            # Determine checks that ran in both scans for accurate comparison
            executed_events = ("completed", "failed")

            result = await session.execute(
                select(CheckLog.check_name)
                .where(CheckLog.scan_id == scan_a_id)
                .where(CheckLog.event.in_(executed_events))
            )
            checks_a = {row[0] for row in result.all()}

            result = await session.execute(
                select(CheckLog.check_name)
                .where(CheckLog.scan_id == scan_b_id)
                .where(CheckLog.event.in_(executed_events))
            )
            checks_b = {row[0] for row in result.all()}

            common_checks = checks_a & checks_b

            # Get fingerprints scoped to common checks (or all if no log data)
            fp_filter_a = [ObservationRecord.scan_id == scan_a_id]
            fp_filter_b = [ObservationRecord.scan_id == scan_b_id]
            if common_checks:
                fp_filter_a.append(ObservationRecord.check_name.in_(common_checks))
                fp_filter_b.append(ObservationRecord.check_name.in_(common_checks))

            result_a = await session.execute(
                select(
                    ObservationRecord.fingerprint,
                    ObservationRecord.title,
                    ObservationRecord.severity,
                ).where(*fp_filter_a)
            )
            fps_a = {
                row[0]: {"title": row[1], "severity": row[2]} for row in result_a.all() if row[0]
            }

            result_b = await session.execute(
                select(
                    ObservationRecord.fingerprint,
                    ObservationRecord.title,
                    ObservationRecord.severity,
                ).where(*fp_filter_b)
            )
            fps_b = {
                row[0]: {"title": row[1], "severity": row[2]} for row in result_b.all() if row[0]
            }

            # Also get observations from checks only in scan B (new checks = all new observations)
            b_only_checks = checks_b - checks_a
            fps_b_only = {}
            if b_only_checks:
                result = await session.execute(
                    select(
                        ObservationRecord.fingerprint,
                        ObservationRecord.title,
                        ObservationRecord.severity,
                    )
                    .where(ObservationRecord.scan_id == scan_b_id)
                    .where(ObservationRecord.check_name.in_(b_only_checks))
                )
                fps_b_only = {
                    row[0]: {"title": row[1], "severity": row[2]} for row in result.all() if row[0]
                }

        new_fps = (set(fps_b.keys()) - set(fps_a.keys())) | set(fps_b_only.keys())
        resolved_fps = set(fps_a.keys()) - set(fps_b.keys())
        recurring_fps = set(fps_a.keys()) & set(fps_b.keys())
        all_b = {**fps_b, **fps_b_only}

        return {
            "scan_a_id": scan_a_id,
            "scan_b_id": scan_b_id,
            "new_count": len(new_fps),
            "resolved_count": len(resolved_fps),
            "recurring_count": len(recurring_fps),
            "new_observations": [all_b[fp] for fp in new_fps],
            "resolved_observations": [fps_a[fp] for fp in resolved_fps],
            "checks_compared": len(common_checks),
            "checks_only_in_a": len(checks_a - checks_b),
            "checks_only_in_b": len(b_only_checks),
        }

    async def get_observation_history(self, fingerprint: str) -> list[dict]:
        """Get status history for an observation fingerprint across scans."""
        async with self._session() as session:
            result = await session.execute(
                select(ObservationStatusHistory)
                .where(ObservationStatusHistory.fingerprint == fingerprint)
                .order_by(ObservationStatusHistory.created_at)
            )
            return [
                {
                    "fingerprint": h.fingerprint,
                    "scan_id": h.scan_id,
                    "status": h.status,
                    "first_seen_scan": h.first_seen_scan,
                    "last_seen_scan": h.last_seen_scan,
                    "created_at": h.created_at.isoformat() if h.created_at else None,
                }
                for h in result.scalars().all()
            ]


class ObservationOverrideRepository(_RepositoryBase):
    """Manage manual observation overrides (accepted risk, false positive)."""

    VALID_STATUSES = {"accepted", "false_positive"}

    async def set_override(
        self,
        fingerprint: str,
        status: str,
        reason: str | None = None,
    ) -> dict:
        """Set or update an override for an observation fingerprint. Upserts."""
        if status not in self.VALID_STATUSES:
            raise ValueError(
                f"Invalid override status: {status}. Must be one of {self.VALID_STATUSES}"
            )

        now = datetime.now(UTC)
        async with self._session() as session:
            result = await session.execute(
                select(ObservationOverride).where(ObservationOverride.fingerprint == fingerprint)
            )
            existing = result.scalar_one_or_none()
            if existing:
                existing.status = status
                existing.reason = reason
                existing.updated_at = now
            else:
                existing = ObservationOverride(
                    fingerprint=fingerprint,
                    status=status,
                    reason=reason,
                    created_at=now,
                    updated_at=now,
                )
                session.add(existing)
            await session.commit()
            return _override_to_dict(existing)

    async def remove_override(self, fingerprint: str) -> bool:
        """Remove an override (reopen the observation). Returns True if existed."""
        async with self._session() as session:
            result = await session.execute(
                select(ObservationOverride).where(ObservationOverride.fingerprint == fingerprint)
            )
            existing = result.scalar_one_or_none()
            if existing is None:
                return False
            await session.execute(
                delete(ObservationOverride).where(ObservationOverride.fingerprint == fingerprint)
            )
            await session.commit()
        logger.info(f"Removed override for fingerprint {fingerprint}")
        return True

    async def get_override(self, fingerprint: str) -> dict | None:
        """Get override for a fingerprint, or None."""
        async with self._session() as session:
            result = await session.execute(
                select(ObservationOverride).where(ObservationOverride.fingerprint == fingerprint)
            )
            override = result.scalar_one_or_none()
            return _override_to_dict(override) if override else None

    async def list_overrides(self, status: str | None = None) -> dict:
        """List all overrides with optional status filter."""
        query = select(ObservationOverride)
        count_query = select(func.count()).select_from(ObservationOverride)
        if status:
            query = query.where(ObservationOverride.status == status)
            count_query = count_query.where(ObservationOverride.status == status)
        query = query.order_by(ObservationOverride.updated_at.desc())

        async with self._session() as session:
            total_result = await session.execute(count_query)
            total = total_result.scalar()
            result = await session.execute(query)
            overrides = [_override_to_dict(o) for o in result.scalars().all()]

        return {"total": total, "overrides": overrides}


def _override_to_dict(o: ObservationOverride) -> dict:
    """Convert an ObservationOverride ORM object to a JSON-safe dict."""
    return {
        "fingerprint": o.fingerprint,
        "status": o.status,
        "reason": o.reason,
        "created_at": o.created_at.isoformat() if o.created_at else None,
        "updated_at": o.updated_at.isoformat() if o.updated_at else None,
    }


# ─── Trend Analysis ─────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


class TrendRepository(_RepositoryBase):
    """Compute trend data across scans for engagements or targets."""

    async def get_engagement_trend(
        self,
        engagement_id: str,
        since: str | None = None,
        until: str | None = None,
        last_n: int | None = None,
    ) -> dict:
        """Get trend data for all completed scans in an engagement."""
        async with self._session() as session:
            query = (
                select(Scan.id)
                .where(Scan.engagement_id == engagement_id)
                .where(Scan.status == "complete")
            )
            query = self._apply_date_filters(query, since, until)
            query = query.order_by(Scan.started_at)
            result = await session.execute(query)
            scan_ids = [row[0] for row in result.all()]

        if last_n and last_n > 0:
            scan_ids = scan_ids[-last_n:]

        if not scan_ids:
            return {
                "data_points": [],
                "averages": {"this_target": {}, "all_targets": {}},
                "metrics": {},
            }

        data_points = await self._build_data_points(scan_ids)
        averages = await self._compute_averages(data_points)
        metrics = await self.compute_metrics(scan_ids)
        return {"data_points": data_points, "averages": averages, "metrics": metrics}

    async def get_target_trend(
        self,
        target_domain: str,
        since: str | None = None,
        until: str | None = None,
        last_n: int | None = None,
    ) -> dict:
        """Get trend data for all completed scans of a target domain."""
        async with self._session() as session:
            query = (
                select(Scan.id)
                .where(Scan.target_domain == target_domain)
                .where(Scan.status == "complete")
            )
            query = self._apply_date_filters(query, since, until)
            query = query.order_by(Scan.started_at)
            result = await session.execute(query)
            scan_ids = [row[0] for row in result.all()]

        if last_n and last_n > 0:
            scan_ids = scan_ids[-last_n:]

        if not scan_ids:
            return {
                "data_points": [],
                "averages": {"this_target": {}, "all_targets": {}},
                "metrics": {},
            }

        data_points = await self._build_data_points(scan_ids)
        averages = await self._compute_averages(data_points)
        metrics = await self.compute_metrics(scan_ids)
        return {"data_points": data_points, "averages": averages, "metrics": metrics}

    @staticmethod
    def _apply_date_filters(query, since: str | None, until: str | None):
        """Apply optional date range filters to a scan query."""
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                query = query.where(Scan.started_at >= since_dt)
            except ValueError:
                pass
        if until:
            try:
                until_dt = datetime.fromisoformat(until)
                query = query.where(Scan.started_at <= until_dt)
            except ValueError:
                pass
        return query

    async def _build_data_points(self, scan_ids: list[str]) -> list[dict]:
        """Build per-scan trend data points."""
        # Get all overridden fingerprints to exclude
        async with self._session() as session:
            result = await session.execute(select(ObservationOverride.fingerprint))
            overridden_fps = {row[0] for row in result.all()}

        data_points = []
        for scan_id in scan_ids:
            point = await self._build_single_point(scan_id, overridden_fps)
            if point:
                data_points.append(point)
        return data_points

    async def _build_single_point(
        self,
        scan_id: str,
        overridden_fps: set[str],
    ) -> dict | None:
        """Build a single trend data point for a scan."""
        async with self._session() as session:
            # Get scan metadata
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan is None:
                return None

            # Get observations, excluding overridden ones
            result = await session.execute(
                select(
                    ObservationRecord.severity,
                    ObservationRecord.suite,
                    ObservationRecord.fingerprint,
                ).where(ObservationRecord.scan_id == scan_id)
            )
            all_observations = result.all()

        # Filter out overridden observations
        observations = [
            (sev, suite, fp) for sev, suite, fp in all_observations if fp not in overridden_fps
        ]

        # Count by severity
        severity_counts = dict.fromkeys(SEVERITY_LEVELS, 0)
        for sev, _, _ in observations:
            key = sev.lower() if sev else "info"
            if key in severity_counts:
                severity_counts[key] += 1

        # Count by suite
        suite_counts: dict[str, int] = {}
        for _, suite, _ in observations:
            s = suite or "unknown"
            suite_counts[s] = suite_counts.get(s, 0) + 1

        # Risk score
        risk_score = sum(
            SEVERITY_WEIGHTS.get(level, 0) * count for level, count in severity_counts.items()
        )

        # Get new/resolved/regressed from ObservationStatusHistory
        new_count = 0
        resolved_count = 0
        regressed_count = 0
        async with self._session() as session:
            result = await session.execute(
                select(ObservationStatusHistory.status, func.count())
                .where(ObservationStatusHistory.scan_id == scan_id)
                .group_by(ObservationStatusHistory.status)
            )
            for status, count in result.all():
                if status == "new":
                    new_count = count
                elif status == "resolved":
                    resolved_count = count
                elif status == "regressed":
                    regressed_count = count

        return {
            "scan_id": scan_id,
            "date": scan.started_at.isoformat() if scan.started_at else None,
            "target_domain": scan.target_domain,
            "total": len(observations),
            **severity_counts,
            "new": new_count,
            "resolved": resolved_count,
            "regressed": regressed_count,
            "risk_score": risk_score,
            "by_suite": suite_counts,
        }

    async def _compute_averages(self, data_points: list[dict]) -> dict:
        """Compute this_target and all_targets averages."""
        this_target = self._average_points(data_points)

        # All-targets average: compute from ALL completed scans in DB
        async with self._session() as session:
            result = await session.execute(
                select(Scan.id).where(Scan.status == "complete").order_by(Scan.started_at)
            )
            all_scan_ids = [row[0] for row in result.all()]

        if all_scan_ids:
            all_points = await self._build_data_points(all_scan_ids)
            all_targets = self._average_points(all_points)
        else:
            all_targets = {}

        return {"this_target": this_target, "all_targets": all_targets}

    @staticmethod
    def _average_points(points: list[dict]) -> dict:
        """Average numeric fields across data points."""
        if not points:
            return {}
        fields = ["total", "critical", "high", "medium", "low", "info", "risk_score"]
        avg = {}
        for field in fields:
            values = [p.get(field, 0) for p in points]
            avg[field] = round(sum(values) / len(values), 1)
        return avg

    async def compute_metrics(self, scan_ids: list[str]) -> dict:
        """Compute regression rate and MTTR for a set of scans.

        Regression rate: % of previously-resolved observations that reappeared.
        MTTR: mean time from first_seen to resolved, broken down by severity.
        """
        if not scan_ids:
            return {"regression_rate": None, "mttr": {}}

        async with self._session() as session:
            # --- Regression rate ---
            # Total resolved across these scans
            result = await session.execute(
                select(func.count())
                .select_from(ObservationStatusHistory)
                .where(ObservationStatusHistory.scan_id.in_(scan_ids))
                .where(ObservationStatusHistory.status == "resolved")
            )
            total_resolved = result.scalar() or 0

            # Total regressed across these scans
            result = await session.execute(
                select(func.count())
                .select_from(ObservationStatusHistory)
                .where(ObservationStatusHistory.scan_id.in_(scan_ids))
                .where(ObservationStatusHistory.status == "regressed")
            )
            total_regressed = result.scalar() or 0

            regression_rate = (
                round(total_regressed / total_resolved * 100, 1) if total_resolved > 0 else None
            )

            # --- MTTR ---
            # For each fingerprint that was resolved in these scans,
            # compute time from first_seen_scan.started_at to the
            # scan where it was resolved.
            result = await session.execute(
                select(
                    ObservationStatusHistory.fingerprint,
                    ObservationStatusHistory.first_seen_scan,
                    ObservationStatusHistory.scan_id,
                )
                .where(ObservationStatusHistory.scan_id.in_(scan_ids))
                .where(ObservationStatusHistory.status == "resolved")
                .where(ObservationStatusHistory.first_seen_scan.isnot(None))
            )
            resolved_entries = result.all()

            # Batch-fetch scan timestamps for MTTR calculation
            all_ref_ids = set()
            for _, first_scan, resolve_scan in resolved_entries:
                if first_scan:
                    all_ref_ids.add(first_scan)
                all_ref_ids.add(resolve_scan)

            scan_times = {}
            if all_ref_ids:
                result = await session.execute(
                    select(Scan.id, Scan.started_at).where(Scan.id.in_(all_ref_ids))
                )
                scan_times = {row[0]: row[1] for row in result.all()}

            # Also need severity per fingerprint for breakdown
            resolved_fps = [fp for fp, _, _ in resolved_entries]
            fp_severity = {}
            if resolved_fps:
                result = await session.execute(
                    select(ObservationRecord.fingerprint, ObservationRecord.severity)
                    .where(ObservationRecord.fingerprint.in_(resolved_fps))
                    .distinct()
                )
                for fp, sev in result.all():
                    fp_severity[fp] = (sev or "info").lower()

        # Compute MTTR per severity
        mttr_by_sev: dict[str, list[float]] = {}
        for fp, first_scan, resolve_scan in resolved_entries:
            first_time = scan_times.get(first_scan)
            resolve_time = scan_times.get(resolve_scan)
            if not first_time or not resolve_time:
                continue
            delta_hours = (resolve_time - first_time).total_seconds() / 3600
            if delta_hours < 0:
                continue
            sev = fp_severity.get(fp, "info")
            mttr_by_sev.setdefault(sev, []).append(delta_hours)

        mttr = {}
        all_times = []
        for sev in SEVERITY_LEVELS:
            times = mttr_by_sev.get(sev, [])
            if times:
                mttr[sev] = round(sum(times) / len(times), 1)
                all_times.extend(times)
        if all_times:
            mttr["overall"] = round(sum(all_times) / len(all_times), 1)

        return {
            "regression_rate": regression_rate,
            "total_resolved": total_resolved,
            "total_regressed": total_regressed,
            "mttr_hours": mttr,
        }


# ─── Adjudication Repository ────────────────────────────────────────────────


class AdjudicationRepository(_RepositoryBase):
    """Persist and query adjudication results."""

    async def bulk_create(self, scan_id: str, results: list[dict]) -> int:
        """Insert adjudication results for a scan. Returns count inserted."""
        if not results:
            return 0

        rows = []
        for r in results:
            rows.append(
                AdjudicationResult(
                    id=r.get("id") or uuid.uuid4().hex[:12],
                    scan_id=scan_id,
                    observation_id=r["observation_id"],
                    original_severity=r["original_severity"],
                    adjudicated_severity=r["adjudicated_severity"],
                    confidence=r["confidence"],
                    approach=r["approach_used"],
                    rationale=r.get("rationale"),
                    factors=r.get("factors"),
                    operator_context_used=r.get("operator_context_used"),
                )
            )

        async with self._session() as session:
            session.add_all(rows)
            await session.commit()

        logger.info(f"Persisted {len(rows)} adjudication results for scan {scan_id}")
        return len(rows)

    async def get_results(self, scan_id: str) -> list[dict]:
        """Get all adjudication results for a scan."""
        async with self._session() as session:
            result = await session.execute(
                select(AdjudicationResult).where(AdjudicationResult.scan_id == scan_id)
            )
            return [_adjudication_to_dict(r) for r in result.scalars().all()]

    async def get_result_for_observation(self, scan_id: str, observation_id: str) -> dict | None:
        """Get adjudication result for a specific observation in a scan."""
        async with self._session() as session:
            result = await session.execute(
                select(AdjudicationResult).where(
                    AdjudicationResult.scan_id == scan_id,
                    AdjudicationResult.observation_id == observation_id,
                )
            )
            row = result.scalar_one_or_none()
            return _adjudication_to_dict(row) if row else None


def _adjudication_to_dict(r: AdjudicationResult) -> dict:
    """Convert an AdjudicationResult ORM object to a JSON-safe dict."""
    return {
        "id": r.id,
        "scan_id": r.scan_id,
        "observation_id": r.observation_id,
        "original_severity": r.original_severity,
        "adjudicated_severity": r.adjudicated_severity,
        "confidence": r.confidence,
        "approach_used": r.approach,
        "rationale": r.rationale,
        "factors": r.factors,
        "operator_context_used": r.operator_context_used,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


class AdvisorRepository(_RepositoryBase):
    """Persist and query scan advisor recommendations."""

    async def bulk_create(self, scan_id: str, recommendations: list[dict]) -> int:
        """Insert advisor recommendations for a scan. Returns count inserted."""
        if not recommendations:
            return 0

        rows = []
        for rec in recommendations:
            rows.append(
                AdvisorRecommendation(
                    scan_id=scan_id,
                    category=rec.get("category"),
                    title=rec.get("title", "Untitled"),
                    description=rec.get("description"),
                    priority=rec.get("priority"),
                    data=rec,
                    created_at=datetime.now(UTC),
                )
            )

        async with self._session() as session:
            session.add_all(rows)
            await session.commit()

        logger.info(f"Persisted {len(rows)} advisor recommendations for scan {scan_id}")
        return len(rows)

    async def get_recommendations(self, scan_id: str) -> list[dict]:
        """Get advisor recommendations for a scan."""
        async with self._session() as session:
            result = await session.execute(
                select(AdvisorRecommendation)
                .where(AdvisorRecommendation.scan_id == scan_id)
                .order_by(AdvisorRecommendation.id)
            )
            return [_advisor_rec_to_dict(r) for r in result.scalars().all()]


def _advisor_rec_to_dict(r: AdvisorRecommendation) -> dict:
    """Convert an AdvisorRecommendation ORM object to a JSON-safe dict."""
    return (
        r.data
        if r.data
        else {
            "category": r.category,
            "title": r.title,
            "description": r.description,
            "priority": r.priority,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
    )


# ─── Triage Repository ────────────────────────────────────────────────


class TriageRepository(_RepositoryBase):
    """Persist and query triage plans and actions."""

    async def create_plan(self, scan_id: str, plan: dict) -> str:
        """Insert a triage plan and its actions. Returns the plan ID."""
        plan_id = plan.get("id") or uuid.uuid4().hex[:12]

        plan_row = TriagePlanRecord(
            id=plan_id,
            scan_id=scan_id,
            summary=plan.get("summary"),
            team_context_available=1 if plan.get("team_context_available") else 0,
            caveat=plan.get("caveat"),
            quick_wins=plan.get("quick_wins", 0),
            strategic_fixes=plan.get("strategic_fixes", 0),
            workstreams=plan.get("workstreams"),
        )

        action_rows = []
        for action in plan.get("actions", []):
            action_rows.append(
                TriageActionRecord(
                    id=action.get("id") or uuid.uuid4().hex[:12],
                    plan_id=plan_id,
                    priority=action.get("priority", 0),
                    action=action.get("action", ""),
                    targets=action.get("targets"),
                    chains_neutralized=action.get("chains_neutralized"),
                    reasoning=action.get("reasoning"),
                    effort_estimate=action.get("effort_estimate"),
                    impact_estimate=action.get("impact_estimate"),
                    feasibility=action.get("feasibility"),
                    remediation_guidance=action.get("remediation_guidance"),
                    observations_resolved=action.get("observations_resolved"),
                    category=action.get("category"),
                )
            )

        async with self._session() as session:
            session.add(plan_row)
            if action_rows:
                session.add_all(action_rows)
            await session.commit()

        logger.info(
            "Persisted triage plan %s with %d actions for scan %s",
            plan_id,
            len(action_rows),
            scan_id,
        )
        return plan_id

    async def get_plan(self, scan_id: str) -> dict | None:
        """Get the triage plan for a scan, including actions."""
        async with self._session() as session:
            result = await session.execute(
                select(TriagePlanRecord).where(TriagePlanRecord.scan_id == scan_id)
            )
            plan_row = result.scalar_one_or_none()
            if not plan_row:
                return None

            actions_result = await session.execute(
                select(TriageActionRecord)
                .where(TriageActionRecord.plan_id == plan_row.id)
                .order_by(TriageActionRecord.priority)
            )
            action_rows = actions_result.scalars().all()

        plan_dict = _triage_plan_to_dict(plan_row)
        plan_dict["actions"] = [_triage_action_to_dict(a) for a in action_rows]
        return plan_dict


def _triage_plan_to_dict(r: TriagePlanRecord) -> dict:
    """Convert a TriagePlanRecord ORM object to a JSON-safe dict."""
    return {
        "id": r.id,
        "scan_id": r.scan_id,
        "generated_at": r.generated_at.isoformat() if r.generated_at else None,
        "summary": r.summary,
        "team_context_available": bool(r.team_context_available),
        "caveat": r.caveat,
        "quick_wins": r.quick_wins,
        "strategic_fixes": r.strategic_fixes,
        "workstreams": r.workstreams,
    }


def _triage_action_to_dict(r: TriageActionRecord) -> dict:
    """Convert a TriageActionRecord ORM object to a JSON-safe dict."""
    return {
        "id": r.id,
        "plan_id": r.plan_id,
        "priority": r.priority,
        "action": r.action,
        "targets": r.targets,
        "chains_neutralized": r.chains_neutralized,
        "reasoning": r.reasoning,
        "effort_estimate": r.effort_estimate,
        "impact_estimate": r.impact_estimate,
        "feasibility": r.feasibility,
        "remediation_guidance": r.remediation_guidance,
        "observations_resolved": r.observations_resolved,
        "category": r.category,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Chat (Phase 35)
# ═══════════════════════════════════════════════════════════════════════════════


class ChatRepository(_RepositoryBase):
    """Persist and query chat messages."""

    async def save_message(
        self,
        msg_id: str,
        session_id: str,
        direction: str,
        text: str,
        agent_type: str | None = None,
        engagement_id: str | None = None,
        route_method: str | None = None,
        ui_context: dict | None = None,
        references: list[dict] | None = None,
        actions: list[dict] | None = None,
    ) -> str:
        """Insert a chat message. Returns the message ID."""
        msg = ChatMessage(
            id=msg_id,
            session_id=session_id,
            engagement_id=engagement_id,
            direction=direction,
            agent_type=agent_type,
            text=text,
            route_method=route_method,
            ui_context=ui_context,
            references=references,
            actions=actions,
        )
        async with self._session() as session:
            session.add(msg)
            await session.commit()
        return msg_id

    async def get_history(
        self,
        session_id: str,
        engagement_id: str | None = None,
        limit: int = 50,
        before: str | None = None,
    ) -> list[dict]:
        """Get chat history, newest first.

        If engagement_id is set, returns messages across all sessions
        in that engagement. Otherwise scoped to session_id only.
        Cleared messages are excluded.
        """
        if engagement_id:
            query = select(ChatMessage).where(
                ChatMessage.engagement_id == engagement_id,
                ChatMessage.cleared == 0,
            )
        else:
            query = select(ChatMessage).where(
                ChatMessage.session_id == session_id,
                ChatMessage.cleared == 0,
            )

        if before:
            # Cursor-based: get timestamp of the cursor message
            async with self._session() as session:
                cursor_result = await session.execute(
                    select(ChatMessage.timestamp).where(ChatMessage.id == before)
                )
                cursor_ts = cursor_result.scalar_one_or_none()
            if cursor_ts:
                query = query.where(ChatMessage.timestamp < cursor_ts)

        query = query.order_by(ChatMessage.timestamp.desc()).limit(limit)

        async with self._session() as session:
            result = await session.execute(query)
            rows = result.scalars().all()

        return [_chat_message_to_dict(r) for r in rows]

    async def clear_session(self, session_id: str) -> int:
        """Mark all messages in a session as cleared. Returns count."""
        async with self._session() as session:
            result = await session.execute(
                select(ChatMessage).where(
                    ChatMessage.session_id == session_id,
                    ChatMessage.cleared == 0,
                )
            )
            rows = result.scalars().all()
            for row in rows:
                row.cleared = 1
            await session.commit()
            return len(rows)

    async def export_engagement_chat(self, engagement_id: str) -> list[dict]:
        """Export all messages for an engagement (including cleared)."""
        query = (
            select(ChatMessage)
            .where(ChatMessage.engagement_id == engagement_id)
            .order_by(ChatMessage.timestamp.asc())
        )
        async with self._session() as session:
            result = await session.execute(query)
            rows = result.scalars().all()
        return [_chat_message_to_dict(r) for r in rows]


def _chat_message_to_dict(r: ChatMessage) -> dict:
    """Convert a ChatMessage ORM object to a JSON-safe dict."""
    return {
        "id": r.id,
        "session_id": r.session_id,
        "engagement_id": r.engagement_id,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        "direction": r.direction,
        "agent_type": r.agent_type,
        "text": r.text,
        "route_method": r.route_method,
        "ui_context": r.ui_context,
        "references": r.references,
        "actions": r.actions,
    }
