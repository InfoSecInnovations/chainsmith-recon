"""Initial schema - scans, findings, chains, check_log

Revision ID: 001
Revises: None
Create Date: 2026-03-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("target_domain", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("checks_total", sa.Integer(), nullable=True),
        sa.Column("checks_completed", sa.Integer(), nullable=True),
        sa.Column("checks_failed", sa.Integer(), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=True),
        sa.Column("scope", sa.JSON(), nullable=True),
        sa.Column("settings", sa.JSON(), nullable=True),
        sa.Column("profile_name", sa.String(), nullable=True),
        sa.Column("scenario_name", sa.String(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("check_name", sa.String(), nullable=False),
        sa.Column("suite", sa.String(), nullable=True),
        sa.Column("target_url", sa.String(), nullable=True),
        sa.Column("host", sa.String(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("raw_data", sa.JSON(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=True),
        sa.Column("verification_status", sa.String(), server_default="pending"),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
    )
    op.create_index("idx_findings_scan_id", "findings", ["scan_id"])
    op.create_index("idx_findings_severity", "findings", ["severity"])
    op.create_index("idx_findings_host", "findings", ["host"])
    op.create_index("idx_findings_fingerprint", "findings", ["fingerprint"])

    op.create_table(
        "chains",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("finding_ids", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=True),
    )
    op.create_index("idx_chains_scan_id", "chains", ["scan_id"])

    op.create_table(
        "check_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("check_name", sa.String(), nullable=False),
        sa.Column("suite", sa.String(), nullable=True),
        sa.Column("event", sa.String(), nullable=False),
        sa.Column("findings_count", sa.Integer(), server_default="0"),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_check_log_scan_id", "check_log", ["scan_id"])


def downgrade() -> None:
    op.drop_table("check_log")
    op.drop_table("chains")
    op.drop_table("findings")
    op.drop_table("scans")
