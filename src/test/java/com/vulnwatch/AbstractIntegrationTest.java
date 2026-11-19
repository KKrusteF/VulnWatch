package com.vulnwatch;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.Conflicts;
import com.vulnwatch.cve.Cve;
import com.vulnwatch.cve.CveRepository;
import com.vulnwatch.cve.Severity;
import com.vulnwatch.events.OutboxPublisher;
import com.vulnwatch.events.OutboxRepository;
import com.vulnwatch.search.CveIndexManager;
import com.vulnwatch.search.CveSearchIndexer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Base class for tests that start the whole application against real Postgres, Elasticsearch and Kafka
 * containers. Spring caches the application context, so all subclasses with the same setup share one app.
 * The scheduled NVD sync and outbox publisher are off, and the Kafka listener only runs in tests that
 * start it with {@link #startKafkaListener()}, so tests in other classes never see each other's events.
 */
@SpringBootTest(properties = {
        "vulnwatch.nvd.enabled=false",
        "vulnwatch.events.publisher-enabled=false",
        "spring.kafka.listener.auto-startup=false",
        "vulnwatch.events.listener-retry.unavailable-initial-backoff=100ms",
        "vulnwatch.events.listener-retry.unavailable-max-backoff=500ms",
        "vulnwatch.events.listener-retry.failure-interval=100ms"})
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
public abstract class AbstractIntegrationTest {

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected CveRepository cveRepository;

    @Autowired
    protected ElasticsearchClient elasticsearchClient;

    @Autowired
    protected CveIndexManager indexManager;

    @Autowired
    protected CveSearchIndexer searchIndexer;

    @Autowired
    protected OutboxRepository outboxRepository;

    @Autowired
    protected OutboxPublisher outboxPublisher;

    @Autowired
    protected KafkaListenerEndpointRegistry kafkaListeners;

    @BeforeEach
    void cleanDatabaseAndIndex() throws IOException {
        outboxRepository.deleteAllInBatch();
        cveRepository.deleteAll();
        indexManager.ensureIndexExists();
        // delete_by_query works on what was visible at the last refresh; a document indexed after that
        // would cause a version conflict, which "proceed" skips instead of failing.
        indexManager.refresh();
        elasticsearchClient.deleteByQuery(d -> d
                .index(indexManager.indexName())
                .query(q -> q.matchAll(m -> m))
                .conflicts(Conflicts.Proceed)
                .refresh(true));
        indexManager.refresh();
    }

    @AfterEach
    void stopKafkaListener() {
        kafkaListeners.stop();
    }

    /** Starts the Kafka consumer that indexes CVE events. It is stopped again after each test. */
    protected void startKafkaListener() {
        kafkaListeners.start();
    }

    /** Saves a CVE with sensible defaults for the fields a test does not care about. */
    protected Cve saveCve(String id, Severity severity, String publishedAt, String... vendors) {
        return saveCve(id, "Description of " + id, severity, publishedAt, vendors);
    }

    /** Saves a CVE with the given description. */
    protected Cve saveCve(String id, String description, Severity severity, String publishedAt, String... vendors) {
        Instant published = Instant.parse(publishedAt);
        Cve cve = new Cve(id, description, severity, new BigDecimal("7.5"), "3.1",
                "Analyzed", published, published.plusSeconds(3600), Set.of(vendors));
        return cveRepository.save(cve);
    }

    /** Copies these CVEs from Postgres into Elasticsearch and makes them searchable immediately. */
    protected void indexAndRefresh(String... ids) {
        searchIndexer.indexByIds(List.of(ids));
        indexManager.refresh();
    }

    /** A CVE ID no other test uses, for tests that run against shared Kafka topics. */
    protected static String uniqueCveId() {
        return "CVE-2099-" + ThreadLocalRandom.current().nextLong(1_000_000_000L, 9_999_999_999L);
    }

    /** Address of the Kafka test container, for test producers and consumers. */
    protected static String kafkaBootstrapServers() {
        return TestcontainersConfiguration.KAFKA.getBootstrapServers();
    }

    /**
     * Reads {@code topic} from the beginning with a fresh consumer group for {@code duration} and returns
     * the records whose key is in {@code keys}. Stops early once every key was seen.
     */
    protected static List<ConsumerRecord<String, String>> readRecords(String topic, Collection<String> keys,
                                                                       Duration duration) {
        Map<String, Object> config = Map.of(
                ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaBootstrapServers(),
                ConsumerConfig.GROUP_ID_CONFIG, "test-reader-" + UUID.randomUUID(),
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest",
                ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class,
                ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        List<ConsumerRecord<String, String>> found = new ArrayList<>();
        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(config)) {
            consumer.subscribe(List.of(topic));
            long deadline = System.nanoTime() + duration.toNanos();
            while (System.nanoTime() < deadline) {
                for (ConsumerRecord<String, String> record : consumer.poll(Duration.ofMillis(200))) {
                    if (keys.contains(record.key())) {
                        found.add(record);
                    }
                }
                if (found.stream().map(ConsumerRecord::key).distinct().count() == keys.size()) {
                    break;
                }
            }
        }
        return found;
    }
}
