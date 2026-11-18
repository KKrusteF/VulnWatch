-- One row per CVE. Postgres is the source of truth for everything VulnWatch knows.
-- The CVE ID is a natural key: it is globally unique, so later ingestion stages can
-- upsert by it (INSERT ... ON CONFLICT (cve_id)) and re-runs never create duplicates.
CREATE TABLE cve (
    cve_id           TEXT PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    description      TEXT        NOT NULL,
    severity         TEXT        NOT NULL DEFAULT 'UNKNOWN'
                     CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN')),
    cvss_score       NUMERIC(3, 1) CHECK (cvss_score BETWEEN 0 AND 10),
    cvss_version     TEXT,
    vuln_status      TEXT        NOT NULL,
    published_at     TIMESTAMPTZ NOT NULL,
    last_modified_at TIMESTAMPTZ NOT NULL
);

-- Listing is "newest first"; cve_id breaks ties so paging is stable.
CREATE INDEX idx_cve_published_at ON cve (published_at DESC, cve_id DESC);
-- Supports filtering by severity while keeping the newest-first order.
CREATE INDEX idx_cve_severity_published_at ON cve (severity, published_at DESC);

-- Vendors affected by a CVE. "vendor" is the lower-case vendor part of a CPE name,
-- e.g. "apache" from cpe:2.3:a:apache:log4j:...
CREATE TABLE cve_vendor (
    cve_id TEXT NOT NULL REFERENCES cve (cve_id) ON DELETE CASCADE,
    vendor TEXT NOT NULL,
    PRIMARY KEY (cve_id, vendor)
);

-- Supports "CVEs for vendor X" and the top-vendors statistic.
CREATE INDEX idx_cve_vendor_vendor ON cve_vendor (vendor);
