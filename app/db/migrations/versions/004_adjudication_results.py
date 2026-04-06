"""Add adjudication_results table for severity adjudication

Revision ID: 004
Revises: 003
Create Date: 2026-04-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "adjudication_results",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("original_severity", sa.String(), nullable=False),
        sa.Column("adjudicated_severity", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("approach", sa.String(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("factors", sa.JSON(), nullable=True),
        sa.Column("operator_context_used", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_adjudication_scan_id", "adjudication_results", ["scan_id"])
    op.create_index("idx_adjudication_finding_id", "adjudication_results", ["finding_id"])


def downgrade() -> None:
    op.drop_index("idx_adjudication_finding_id", table_name="adjudication_results")
    op.drop_index("idx_adjudication_scan_id", table_name="adjudication_results")
    op.drop_table("adjudication_results")
