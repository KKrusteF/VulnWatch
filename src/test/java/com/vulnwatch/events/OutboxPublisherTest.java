package com.vulnwatch.events;

import com.vulnwatch.AbstractIntegrationTest;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.kafka.KafkaException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;

/**
 * Tests publishing the outbox to a real Kafka broker. Uses its own topic so its messages never reach
 * the indexing consumer, and a batch size of 3 so draining the outbox needs several batches.
 */
@TestPropertySource(properties = {
        "vulnwatch.events.topic=vulnwatch.outbox-test-events",
        "vulnwatch.events.publish-batch-size=3"})
class OutboxPublisherTest extends AbstractIntegrationTest {

    private static final String TOPIC = "vulnwatch.outbox-test-events";
    private static final Duration READ_TIMEOUT = Duration.ofSeconds(20);

    // The real template, which a test can make fail on purpose. Spring Boot declares it as
    // KafkaTemplate<?, ?>, so the field has to use the same wildcard type.
    @MockitoSpyBean
    KafkaTemplate<?, ?> kafkaTemplate;

    @Test
    void publishesEveryRowWithTheCveIdAsKeyAndEmptiesTheOutbox() {
        List<String> ids = saveOutboxRows(2);

        assertThat(outboxPublisher.publishPending()).isEqualTo(2);

        List<ConsumerRecord<String, String>> records = readRecords(TOPIC, ids, READ_TIMEOUT);
        assertThat(records).extracting(ConsumerRecord::key).containsExactlyInAnyOrderElementsOf(ids);
        assertThat(records).allSatisfy(record -> {
            assertThat(record.value()).startsWith("{").contains("\"cveId\":\"" + record.key() + "\"")
                    .contains("\"type\":\"CREATED\"")
                    // Timestamps are ISO-8601 strings, not numbers.
                    .contains("\"lastModifiedAt\":\"2026-11-18T12:00:00Z\"")
                    .contains("\"occurredAt\":\"2026-11-18T12:00:00Z\"");
            // Plain JSON: no Java class name header.
            assertThat(record.headers().lastHeader("__TypeId__")).isNull();
        });
        assertThat(outboxRepository.count()).isZero();

        assertThat(outboxPublisher.publishPending()).isZero();
    }

    @Test
    void failedSendKeepsTheRowsForTheNextAttempt() {
        List<String> ids = saveOutboxRows(2);
        doReturn(CompletableFuture.failedFuture(new KafkaException("broker down")))
                .when(template()).send(anyString(), anyString(), any());

        assertThatThrownBy(() -> outboxPublisher.publishPending())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Kafka did not acknowledge");
        assertThat(outboxRepository.count()).isEqualTo(2);

        Mockito.reset(kafkaTemplate); // Kafka is back
        assertThat(outboxPublisher.publishPending()).isEqualTo(2);

        assertThat(readRecords(TOPIC, ids, READ_TIMEOUT)).extracting(ConsumerRecord::key)
                .containsExactlyInAnyOrderElementsOf(ids);
        assertThat(outboxRepository.count()).isZero();
    }

    @Test
    void sendsAllRowsWhenThereAreMoreThanOneBatch() {
        List<String> ids = saveOutboxRows(7);

        assertThat(outboxPublisher.publishPending()).isEqualTo(7);

        assertThat(readRecords(TOPIC, ids, READ_TIMEOUT)).extracting(ConsumerRecord::key)
                .containsExactlyInAnyOrderElementsOf(ids);
        assertThat(outboxRepository.count()).isZero();
    }

    @SuppressWarnings("unchecked")
    private KafkaTemplate<String, Object> template() {
        return (KafkaTemplate<String, Object>) kafkaTemplate;
    }

    private List<String> saveOutboxRows(int count) {
        List<String> ids = IntStream.range(0, count).mapToObj(i -> uniqueCveId()).toList();
        Instant now = Instant.parse("2026-11-18T12:00:00Z");
        outboxRepository.saveAll(ids.stream()
                .map(id -> new OutboxEvent(id, CveEvent.CREATED, now, now))
                .toList());
        return ids;
    }
}
