"""Phase 31: Add scan status columns and advisor_recommendations table

Extends the scans table with status fields previously held only in
AppState (adjudication_status, chain_status, etc.) and creates the
advisor_recommendations table for persisting scan advisor output.

Revision ID: 005
Revises: 004
Create Date: 2026-04-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add status columns to scans table
    with op.batch_alter_table("scans") as batch_op:
        batch_op.add_column(sa.Column("adjudication_status", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("adjudication_error", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("chain_status", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("chain_error", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("chain_llm_analysis", sa.JSON(), nullable=True))

    # Set defaults for existing rows
    op.execute("UPDATE scans SET adjudication_status = 'idle' WHERE adjudication_status IS NULL")
    op.execute("UPDATE scans SET chain_status = 'idle' WHERE chain_status IS NULL")

    # Create advisor_recommendations table
    op.create_table(
        "advisor_recommendations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("priority", sa.String(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_advisor_rec_scan_id", "advisor_recommendations", ["scan_id"])


def downgrade() -> None:
    op.drop_index("idx_advisor_rec_scan_id", table_name="advisor_recommendations")
    op.drop_table("advisor_recommendations")

    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_column("chain_llm_analysis")
        batch_op.drop_column("chain_error")
        batch_op.drop_column("chain_status")
        batch_op.drop_column("adjudication_error")
        batch_op.drop_column("adjudication_status")
