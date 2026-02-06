-- =============================================================================
-- Sentinel NetLab - PostgreSQL Initialization Script
-- Runs on first container start
-- =============================================================================

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- =============================================================================
-- Sensors Table
-- =============================================================================
CREATE TABLE IF NOT EXISTS sensors (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128),
    status VARCHAR(20) DEFAULT 'offline',
    last_heartbeat TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    config JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_sensors_status ON sensors(status);

-- =============================================================================
-- Telemetry Table (Hypertable for time-series)
-- =============================================================================
CREATE TABLE IF NOT EXISTS telemetry (
    id BIGSERIAL,
    sensor_id VARCHAR(64) NOT NULL,
    batch_id VARCHAR(64),
    timestamp TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ DEFAULT NOW(),
    
    bssid VARCHAR(17) NOT NULL,
    ssid VARCHAR(32),
    channel SMALLINT,
    rssi_dbm SMALLINT,
    frequency_mhz SMALLINT,
    
    security VARCHAR(20),
    capabilities JSONB DEFAULT '{}'::jsonb,
    rsn_info JSONB DEFAULT '{}'::jsonb,
    raw_data JSONB DEFAULT '{}'::jsonb,
    
    PRIMARY KEY (timestamp, id)
);

-- Convert to hypertable (TimescaleDB)
-- P1 Scale: Partition by time AND sensor_id (Space Partitioning)
SELECT create_hypertable('telemetry', 'timestamp', 
    partitioning_column => 'sensor_id', 
    number_partitions => 4,
    if_not_exists => TRUE
);

-- Indexes
CREATE INDEX idx_telemetry_sensor_id ON telemetry(sensor_id, timestamp DESC);
CREATE INDEX idx_telemetry_bssid ON telemetry(bssid, timestamp DESC);

-- Compression (Active after 7 days)
ALTER TABLE telemetry SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'sensor_id',
    timescaledb.compress_orderby = 'timestamp DESC'
);
SELECT add_compression_policy('telemetry', INTERVAL '7 days', if_not_exists => TRUE);

-- Retention policy: 30 days (Raw data)
-- Keeps storage usage predictable.
SELECT add_retention_policy('telemetry', INTERVAL '30 days', if_not_exists => TRUE);

-- =============================================================================
-- Continuous Aggregates (Downsampling)
-- =============================================================================

-- 1 Minute Aggregation (Signal quality monitoring)
CREATE MATERIALIZED VIEW telemetry_1m
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 minute', timestamp) AS bucket,
    sensor_id,
    AVG(rssi_dbm) AS avg_rssi,
    COUNT(*) AS frame_count,
    COUNT(DISTINCT bssid) AS unique_bssids
FROM telemetry
GROUP BY bucket, sensor_id;

SELECT add_continuous_aggregate_policy('telemetry_1m',
    start_offset => INTERVAL '1 day',
    end_offset => INTERVAL '1 minute',
    schedule_interval => INTERVAL '1 minute');

-- 1 Hour Aggregation (Long-term trends)
CREATE MATERIALIZED VIEW telemetry_1h
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', timestamp) AS bucket,
    sensor_id,
    AVG(rssi_dbm) AS avg_rssi,
    SUM(COUNT(*))::BIGINT AS frame_count, -- Sum of counts
    COUNT(DISTINCT bssid) AS unique_bssids
FROM telemetry
GROUP BY bucket, sensor_id;

SELECT add_continuous_aggregate_policy('telemetry_1h',
    start_offset => INTERVAL '7 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour');


-- =============================================================================
-- Ingest Jobs (DB-Backed Queue)
-- =============================================================================
CREATE TABLE IF NOT EXISTS ingest_jobs (
    job_id VARCHAR(64) PRIMARY KEY, -- batch_id
    sensor_id VARCHAR(64) NOT NULL,
    received_at TIMESTAMPTZ DEFAULT NOW(),
    
    status VARCHAR(20) DEFAULT 'queued', -- queued, processing, done, failed
    payload JSONB, -- Compressed/Raw batch data
    
    attempts INTEGER DEFAULT 0,
    next_attempt_at TIMESTAMPTZ DEFAULT NOW(),
    error_msg TEXT
);

CREATE INDEX idx_jobs_status_next ON ingest_jobs(status, next_attempt_at);
-- No idx_ingest_received needed if we prioritize by next_attempt_at

-- =============================================================================
-- Alerts Table
-- =============================================================================
CREATE TABLE IF NOT EXISTS alerts (
    id VARCHAR(32) PRIMARY KEY,
    sensor_id VARCHAR(64) REFERENCES sensors(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    
    bssid VARCHAR(17),
    ssid VARCHAR(32),
    
    evidence JSONB DEFAULT '{}'::jsonb,
    reason_codes JSONB DEFAULT '[]'::jsonb,
    
    confidence DOUBLE PRECISION,
    impact DOUBLE PRECISION,
    risk_score DOUBLE PRECISION,
    
    mitre_attack VARCHAR(20),
    
    status VARCHAR(20) DEFAULT 'open',
    resolved_at TIMESTAMPTZ,
    resolved_by VARCHAR(64)
);

CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_type ON alerts(alert_type);

-- =============================================================================
-- API Tokens Table
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_tokens (
    token_id VARCHAR(32) PRIMARY KEY,
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(128),
    role VARCHAR(20) NOT NULL,
    sensor_id VARCHAR(64),
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used TIMESTAMPTZ,
    last_sequence BIGINT DEFAULT 0,
    
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_tokens_hash ON api_tokens(token_hash);

-- =============================================================================
-- Audit Log Table
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    
    event_type VARCHAR(50) NOT NULL,
    actor VARCHAR(64),
    resource VARCHAR(128),
    action VARCHAR(50),
    
    details JSONB DEFAULT '{}'::jsonb,
    ip_address INET
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_event_type ON audit_log(event_type);

-- =============================================================================
-- Initial Data
-- =============================================================================

-- Create default admin token (hash of 'admin-token-dev')
-- In production, generate a real token and store the hash
INSERT INTO api_tokens (token_id, token_hash, name, role, expires_at)
VALUES (
    'admin-01',
    encode(sha256('admin-token-dev'::bytea), 'hex'),
    'Default Admin Token',
    'admin',
    NOW() + INTERVAL '365 days'
) ON CONFLICT (token_id) DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sentinel;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel;

-- Done
SELECT 'Database initialization complete' AS status;
