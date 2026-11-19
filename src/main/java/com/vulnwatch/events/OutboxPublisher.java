package com.vulnwatch.events;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Drains the outbox to Kafka every publish-interval. The transactional work lives in
 * {@link OutboxBatchPublisher}, a separate bean, because {@code @Transactional} only applies to calls
 * that come in through Spring's proxy, not to calls a bean makes on itself.
 */
@Component
public class OutboxPublisher {

    private static final Logger log = LoggerFactory.getLogger(OutboxPublisher.class);

    private final OutboxBatchPublisher batchPublisher;
    private final EventsProperties properties;

    public OutboxPublisher(OutboxBatchPublisher batchPublisher, EventsProperties properties) {
        this.batchPublisher = batchPublisher;
        this.properties = properties;
    }

    /** Sends batches until the outbox is empty. Returns the number of events sent. */
    public int publishPending() {
        int total = 0;
        int sent;
        while ((sent = batchPublisher.publishBatch()) > 0) {
            total += sent;
        }
        return total;
    }

    @Scheduled(fixedDelayString = "${vulnwatch.events.publish-interval}")
    public void publishPeriodically() {
        if (!properties.publisherEnabled()) {
            return;
        }
        try {
            int sent = publishPending();
            if (sent > 0) {
                log.info("Published {} CVE events to Kafka", sent);
            }
        } catch (Exception e) {
            // Only the message: this runs every second, and the rows stay in the outbox for the next try.
            log.warn("Publishing outbox events failed, will retry: {}", e.getMessage());
        }
    }
}
