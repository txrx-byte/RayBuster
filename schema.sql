-- D1 Database Schema for Raybuster Platform
-- Run with: wrangler d1 execute raybuster-anomalies --file=schema.sql

-- Telemetry/Anomaly Storage Table
-- Only stores flagged traffic (ANOMALY, BOT) to conserve write capacity
CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ray_id TEXT NOT NULL,           -- Cloudflare Ray ID (unique per request)
    ip_raw TEXT NOT NULL,           -- Raw IP address (for WAF blocking)
    ip_hash TEXT,                   -- Hashed IP (for privacy/GDPR compliance)
    country_code TEXT,              -- Claimed country code
    colo_code TEXT,                 -- Cloudflare Edge datacenter code
    asn INTEGER,                    -- Autonomous System Number
    tcp_rtt INTEGER DEFAULT 0,      -- TCP Connection RTT (ms)
    app_rtt INTEGER DEFAULT 0,      -- Application/HTTP RTT (ms)
    verdict TEXT DEFAULT 'CLEAN',   -- CLEAN, ANOMALY, BOT
    reason TEXT,                    -- Heuristic reason string
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_ray ON telemetry(ray_id);
CREATE INDEX IF NOT EXISTS idx_ip ON telemetry(ip_raw);
CREATE INDEX IF NOT EXISTS idx_created ON telemetry(created_at);
CREATE INDEX IF NOT EXISTS idx_verdict ON telemetry(verdict);

-- Blocklist Table (for one-click WAF sync)
-- Stores IPs/ASNs that have been confirmed malicious
CREATE TABLE IF NOT EXISTS blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL,       -- IP address, CIDR, or ASN
    identifier_type TEXT NOT NULL,  -- 'IP', 'CIDR', 'ASN'
    reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME             -- NULL = permanent block
);

CREATE INDEX IF NOT EXISTS idx_blocklist ON blocklist(identifier);

-- Audit Log Table (for admin actions)
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,           -- 'BLOCK', 'UNBLOCK', 'EXPORT', etc.
    admin_id TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
