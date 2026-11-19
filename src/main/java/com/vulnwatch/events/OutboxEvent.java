package com.vulnwatch.events;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * A row in {@code cve_outbox}: an event that still has to be sent to Kafka.
 */
@Entity
@Table(name = "cve_outbox")
public class OutboxEvent {

    // A sequence instead of an IDENTITY column: Hibernate reserves 50 IDs with one call and can then send
    // many INSERTs in one JDBC batch. With IDENTITY it would have to insert the rows one at a time.
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "cve_outbox_seq")
    @SequenceGenerator(name = "cve_outbox_seq", sequenceName = "cve_outbox_seq", allocationSize = 50)
    private Long id;

    @Column(name = "cve_id")
    private String cveId;

    private String eventType;

    private Instant lastModifiedAt;

    private Instant createdAt;

    /** Required by JPA. */
    protected OutboxEvent() {
    }

    public OutboxEvent(String cveId, String eventType, Instant lastModifiedAt, Instant createdAt) {
        this.cveId = cveId;
        this.eventType = eventType;
        this.lastModifiedAt = lastModifiedAt;
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public String getCveId() {
        return cveId;
    }

    public String getEventType() {
        return eventType;
    }

    public Instant getLastModifiedAt() {
        return lastModifiedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    /** The Kafka message for this row. */
    public CveEvent toEvent() {
        return new CveEvent(cveId, eventType, lastModifiedAt, createdAt);
    }
}
