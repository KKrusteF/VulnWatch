package com.vulnwatch.events;

import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Sends one batch of outbox rows to Kafka and deletes them once Kafka has acknowledged every one.
 * If anything fails, the transaction rolls back and the rows are sent again later (at-least-once).
 */
@Component
public class OutboxBatchPublisher {

    private final OutboxRepository repository;
    private final KafkaTemplate<String, CveEvent> kafkaTemplate;
    private final EventsProperties properties;

    public OutboxBatchPublisher(OutboxRepository repository, KafkaTemplate<String, CveEvent> kafkaTemplate,
                                EventsProperties properties) {
        this.repository = repository;
        this.kafkaTemplate = kafkaTemplate;
        this.properties = properties;
    }

    /**
     * Publishes up to publish-batch-size rows and returns how many were sent.
     * The transaction stays open while waiting for Kafka on purpose: the row locks taken by
     * {@link OutboxRepository#lockOldest} are what keep two publishers apart. The wait is bounded by
     * the batch size and send-timeout.
     */
    @Transactional
    public int publishBatch() {
        List<OutboxEvent> rows = repository.lockOldest(properties.publishBatchSize());
        if (rows.isEmpty()) {
            return 0;
        }
        // Send everything first and wait once, so the producer can group the messages.
        List<CompletableFuture<SendResult<String, CveEvent>>> sends = rows.stream()
                .map(row -> kafkaTemplate.send(properties.topic(), row.getCveId(), row.toEvent()))
                .toList();
        try {
            CompletableFuture.allOf(sends.toArray(CompletableFuture[]::new))
                    .get(properties.sendTimeout().toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for Kafka", e);
        } catch (ExecutionException | TimeoutException e) {
            throw new IllegalStateException("Kafka did not acknowledge " + rows.size() + " outbox events", e);
        }
        repository.deleteAllByIdInBatch(rows.stream().map(OutboxEvent::getId).toList());
        return rows.size();
    }
}
