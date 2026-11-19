-- Transactional outbox: one row per CVE that was created or updated, written in the same
-- transaction as the CVE itself. A publisher sends the rows to Kafka and then deletes them,
-- so the table normally stays near empty.

-- Hibernate takes 50 IDs per sequence call (allocationSize 50), so the step must match.
CREATE SEQUENCE cve_outbox_seq INCREMENT BY 50;

CREATE TABLE cve_outbox (
    id               BIGINT      PRIMARY KEY,
    cve_id           TEXT        NOT NULL,
    event_type       TEXT        NOT NULL CHECK (event_type IN ('CREATED', 'UPDATED')),
    last_modified_at TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL
);
