"""add_sensor_keys_table

Revision ID: a1b2c3d4e5f6
Revises: 5096ce2e55f5
Create Date: 2026-03-20 23:29:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | Sequence[str] | None = "5096ce2e55f5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add sensor_keys table for per-sensor HMAC key provisioning."""
    op.create_table(
        "sensor_keys",
        sa.Column(
            "sensor_id",
            sa.String(length=64),
            sa.ForeignKey("sensors.id"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=True,
        ),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.true(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Drop sensor_keys table."""
    op.drop_table("sensor_keys")
