package com.vulnwatch.search;

import co.elastic.clients.elasticsearch._types.FieldValue;
import co.elastic.clients.elasticsearch._types.mapping.DynamicMapping;
import co.elastic.clients.elasticsearch._types.mapping.TypeMapping;
import com.vulnwatch.AbstractIntegrationTest;
import com.vulnwatch.cve.CveData;
import com.vulnwatch.cve.CveUpsertService;
import com.vulnwatch.cve.Severity;
import com.vulnwatch.events.CveEvent;
import com.vulnwatch.events.EventsProperties;
import com.vulnwatch.events.OutboxEvent;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end tests of the indexing consumer through a real Kafka broker: outbox to topic to listener to
 * Elasticsearch. Every test uses fresh CVE IDs, because events from earlier tests may still be in the topic.
 */
class CveEventListenerTest extends AbstractIntegrationTest {

    private static final Duration WAIT = Duration.ofSeconds(30);

    @Autowired
    KafkaTemplate<String, CveEvent> kafkaTemplate;

    @Autowired
    EventsProperties eventsProperties;

    @Autowired
    CveUpsertService upsertService;

    // The real indexer, which a test can make fail on purpose.
    @MockitoSpyBean
    CveSearchIndexer spiedIndexer;

    @BeforeEach
    void startListener() {
        startKafkaListener();
    }

    @Test
    void publishedCveBecomesSearchable() throws Exception {
        String id = uniqueCveId();
        saveCve(id, "Heap overflow in the zebrafish parser", Severity.HIGH, "2026-11-01T00:00:00Z");
        saveOutboxRow(id);

        outboxPublisher.publishPending();

        await().atMost(WAIT).until(() -> documentExists(id));
        indexManager.refresh();
        mockMvc.perform(get("/api/cves/search").param("q", "zebrafish"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[0].id").value(id));
    }

    @Test
    void sameEventDeliveredTwiceLeavesOneDocument() throws Exception {
        String id = uniqueCveId();
        saveCve(id, Severity.HIGH, "2026-11-01T00:00:00Z");
        CveEvent event = event(id);

        kafkaTemplate.send(eventsProperties.topic(), id, event).get();
        kafkaTemplate.send(eventsProperties.topic(), id, event).get();

        verify(spiedIndexer, timeout(WAIT.toMillis()).times(2)).indexByIds(List.of(id));
        indexManager.refresh();
        assertThat(documentsWithId(id)).isEqualTo(1);
    }

    @Test
    void invalidMessageGoesToTheDeadLetterTopicAndLaterEventsAreStillIndexed() throws Exception {
        String id = uniqueCveId();
        saveCve(id, Severity.HIGH, "2026-11-01T00:00:00Z");

        // Same key, so both land in the same partition: the bad message must not block the good one.
        try (KafkaProducer<String, String> producer = rawProducer()) {
            producer.send(new ProducerRecord<>(eventsProperties.topic(), id, "this is not json")).get();
        }
        kafkaTemplate.send(eventsProperties.topic(), id, event(id)).get();

        await().atMost(WAIT).until(() -> documentExists(id));
        List<ConsumerRecord<String, String>> deadLetters =
                readRecords(eventsProperties.deadLetterTopic(), List.of(id), WAIT);
        assertThat(deadLetters).extracting(ConsumerRecord::value).containsExactly("this is not json");
    }

    @Test
    void unavailableElasticsearchIsRetriedUntilItRecovers() {
        String id = uniqueCveId();
        saveCve(id, Severity.HIGH, "2026-11-01T00:00:00Z");
        AtomicInteger attempts = new AtomicInteger();
        doAnswer(invocation -> {
            Collection<String> ids = invocation.getArgument(0);
            if (ids.contains(id) && attempts.incrementAndGet() <= 3) {
                throw new SearchUnavailableException("Elasticsearch is down (test)", null);
            }
            return invocation.callRealMethod();
        }).when(spiedIndexer).indexByIds(anyCollection());
        saveOutboxRow(id);

        outboxPublisher.publishPending();

        await().atMost(WAIT).until(() -> documentExists(id));
        assertThat(attempts.get()).isEqualTo(4);
        assertThat(readRecords(eventsProperties.deadLetterTopic(), List.of(id), Duration.ofSeconds(3))).isEmpty();
    }

    @Test
    void eventForACveThatIsNotStoredIsIgnored() throws IOException {
        String id = uniqueCveId();

        kafkaTemplate.send(eventsProperties.topic(), id, event(id));

        verify(spiedIndexer, timeout(WAIT.toMillis()).times(1)).indexByIds(List.of(id));
        assertThat(documentExists(id)).isFalse();
        assertThat(readRecords(eventsProperties.deadLetterTopic(), List.of(id), Duration.ofSeconds(3))).isEmpty();
    }

    @Test
    void indexDeletedWhileRunningIsRecreatedFromTheExplicitMapping() throws Exception {
        String id = uniqueCveId();
        elasticsearchClient.indices().delete(d -> d.index(indexManager.indexName()));

        Instant now = Instant.now();
        upsertService.upsertAll(List.of(new CveData(id, "Use after free in the walrus codec", Severity.HIGH,
                new BigDecimal("8.1"), "3.1", "Analyzed", now, now, Set.of("walrus"))));
        outboxPublisher.publishPending();

        // The first attempt finds no index, recreates it and fails on purpose; the retry indexes the CVE.
        await().atMost(WAIT).ignoreExceptions().until(() -> documentExists(id));
        TypeMapping mapping = elasticsearchClient.indices()
                .getMapping(g -> g.index(indexManager.indexName()))
                .result().get(indexManager.indexName()).mappings();
        assertThat(mapping.dynamic()).isEqualTo(DynamicMapping.Strict);
        assertThat(mapping.properties().get("description").isText()).isTrue();
        assertThat(mapping.properties().get("description").text().analyzer()).isEqualTo("english");
        assertThat(readRecords(eventsProperties.deadLetterTopic(), List.of(id), Duration.ofSeconds(3))).isEmpty();
    }

    private void saveOutboxRow(String id) {
        Instant now = Instant.now();
        outboxRepository.save(new OutboxEvent(id, CveEvent.CREATED, now, now));
    }

    private static CveEvent event(String id) {
        Instant now = Instant.now();
        return new CveEvent(id, CveEvent.UPDATED, now, now);
    }

    private boolean documentExists(String id) throws IOException {
        // A get by ID sees the document right away, without waiting for a refresh.
        return elasticsearchClient.exists(e -> e.index(indexManager.indexName()).id(id)).value();
    }

    private long documentsWithId(String id) throws IOException {
        return elasticsearchClient.count(c -> c.index(indexManager.indexName())
                .query(q -> q.term(t -> t.field("id").value(FieldValue.of(id))))).count();
    }

    private static KafkaProducer<String, String> rawProducer() {
        return new KafkaProducer<>(Map.of(
                ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaBootstrapServers(),
                ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class,
                ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class));
    }
}
