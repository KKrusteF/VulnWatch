package com.vulnwatch.events;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * The {@code vulnwatch.events.*} settings: the Kafka topic, how the outbox is published and how the
 * indexing consumer retries failed events.
 */
@ConfigurationProperties("vulnwatch.events")
@Validated
public record EventsProperties(
        @NotBlank String topic,
        @Min(1) int partitions,
        boolean publisherEnabled,
        @NotNull Duration publishInterval,
        @Min(1) @Max(10_000) int publishBatchSize,
        @NotNull Duration sendTimeout,
        @NotNull @Valid ListenerRetry listenerRetry) {

    /** The dead letter topic is the main topic's name with ".DLT" appended (Spring Kafka's convention). */
    public String deadLetterTopic() {
        return topic + ".DLT";
    }

    /**
     * Retries in the consumer: without limit while Elasticsearch is unavailable, and a few quick
     * attempts for any other error before the event goes to the dead letter topic.
     */
    public record ListenerRetry(
            @NotNull Duration unavailableInitialBackoff,
            @NotNull Duration unavailableMaxBackoff,
            @NotNull Duration failureInterval,
            @Min(0) int failureRetries) {
    }
}
