"""Add engagements, engagement_id on scans, finding_status_history, scan_comparisons

Revision ID: 002
Revises: 001
Create Date: 2026-03-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Engagements table
    op.create_table(
        "engagements",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("target_domain", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("client_name", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(), server_default="active"),
        sa.Column("metadata", sa.JSON(), nullable=True),
    )

    # Add engagement_id to scans
    op.add_column("scans", sa.Column("engagement_id", sa.String(), nullable=True))

    # Finding status history
    op.create_table(
        "finding_status_history",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("first_seen_scan", sa.String(), nullable=True),
        sa.Column("last_seen_scan", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_fsh_fingerprint", "finding_status_history", ["fingerprint"])
    op.create_index("idx_fsh_scan_id", "finding_status_history", ["scan_id"])

    # Scan comparisons
    op.create_table(
        "scan_comparisons",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_a_id", sa.String(), nullable=False),
        sa.Column("scan_b_id", sa.String(), nullable=False),
        sa.Column("new_findings", sa.Integer(), nullable=True),
        sa.Column("resolved", sa.Integer(), nullable=True),
        sa.Column("recurring", sa.Integer(), nullable=True),
        sa.Column("regressed", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("scan_a_id", "scan_b_id", name="uq_scan_comparison"),
    )


def downgrade() -> None:
    op.drop_table("scan_comparisons")
    op.drop_table("finding_status_history")
    op.drop_column("scans", "engagement_id")
    op.drop_table("engagements")
