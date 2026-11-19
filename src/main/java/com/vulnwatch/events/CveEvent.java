package com.vulnwatch.events;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.Instant;

/**
 * The message sent to Kafka when a CVE was created or updated. It only says which CVE changed;
 * consumers read the current data from Postgres, so old or repeated messages are harmless.
 */
public record CveEvent(
        String cveId,
        String type,
        // ISO-8601 text such as "2026-11-18T12:00:00Z" instead of a number, so the message is readable.
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant lastModifiedAt,
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant occurredAt) {

    public static final String CREATED = "CREATED";
    public static final String UPDATED = "UPDATED";
}
