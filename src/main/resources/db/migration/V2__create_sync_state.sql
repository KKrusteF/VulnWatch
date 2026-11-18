-- One row per feed VulnWatch syncs from (for now only 'nvd-cve').
-- last_synced_until is the end of the last time window that was fully stored;
-- the next sync continues from there, so restarts never lose or repeat a whole window.
CREATE TABLE sync_state (
    source            TEXT PRIMARY KEY,
    last_synced_until TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL
);
