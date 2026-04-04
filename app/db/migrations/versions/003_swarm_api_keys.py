"""Add swarm_api_keys table for agent authentication

Revision ID: 003
Revises: 002
Create Date: 2026-03-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "swarm_api_keys",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("key_hash", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_swarm_api_keys_hash", "swarm_api_keys", ["key_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("idx_swarm_api_keys_hash", table_name="swarm_api_keys")
    op.drop_table("swarm_api_keys")
