-- =============================================================================
-- Sentinel NetLab - PostgreSQL Initialization Script
-- =============================================================================
-- Note: Schema validation and creation is now handled by Alembic Migrations.
-- This script only sets up extensions and global permissions.

-- Enable extensions (Must be done by superuser or before migrations)
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Grant permissions (if needed, usually role based)
-- Ensure 'sentinel' user has permissions if not owner
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sentinel;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel;

SELECT 'Database initialization complete (Extensions Only)' AS status;
