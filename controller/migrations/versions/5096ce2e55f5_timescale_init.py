"""timescale_init

Revision ID: 5096ce2e55f5
Revises: 4085bd1d44e4
Create Date: 2026-02-08 13:30:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "5096ce2e55f5"
down_revision: str | Sequence[str] | None = "4085bd1d44e4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply TimescaleDB optimizations (Postgres only)."""
    conn = op.get_bind()
    if conn.dialect.name != "postgresql":
        return

    # 1. Extensions (Managed by init-db.sql usually, but we assume they exist)
    # op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE")
    # op.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")

    # 2. Convert to Hypertable
    # partitioning_column: sensor_id
    # time_column: timestamp
    op.execute("""
        SELECT create_hypertable('telemetry', 'timestamp',
            partitioning_column => 'sensor_id',
            number_partitions => 4,
            if_not_exists => TRUE,
            migrate_data => TRUE
        );
    """)

    # 3. Enable Compression
    # Segment by sensor_id (efficient query by sensor)
    # Order by timestamp DESC (recent first)
    op.execute("""
        ALTER TABLE telemetry SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'sensor_id',
            timescaledb.compress_orderby = 'timestamp DESC'
        );
    """)

    # 4. Add Compression Policy (Compress chunks older than 7 days)
    op.execute(
        "SELECT add_compression_policy('telemetry', INTERVAL '7 days', if_not_exists => TRUE);"
    )

    # 5. Add Retention Policy (Drop chunks older than 30 days)
    # WARNING: This deletes data! Ensure this matches requirements.
    op.execute(
        "SELECT add_retention_policy('telemetry', INTERVAL '30 days', if_not_exists => TRUE);"
    )


def downgrade() -> None:
    """Revert TimescaleDB optimizations."""
    conn = op.get_bind()
    if conn.dialect.name != "postgresql":
        return

    # We generally don't drop extensions as checking for them is complex
    # and they might be used by other things.
    # But we can try to undo policies.

    try:
        op.execute("SELECT remove_retention_policy('telemetry', if_exists => TRUE);")
        op.execute("SELECT remove_compression_policy('telemetry', if_exists => TRUE);")

        # Disabling compression on the table requires decompressing chunks first,
        # which can be heavy. For downgrade, we might just leave usage on.
        # But technically we should:
        # op.execute("ALTER TABLE telemetry SET (timescaledb.compress = false);")
    except Exception as e:
        print(f"Warning during downgrade: {e}")
