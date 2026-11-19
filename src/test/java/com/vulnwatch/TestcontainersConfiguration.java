package com.vulnwatch;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.elasticsearch.ElasticsearchContainer;
import org.testcontainers.kafka.KafkaContainer;

/**
 * Starts a throwaway Postgres, Elasticsearch and Kafka in Docker for tests. {@code @ServiceConnection}
 * makes Spring Boot point the datasource, the Elasticsearch client and Kafka at these containers.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

    // Static, so every Spring test context in this JVM gets the same containers instead of starting
    // new ones (some test classes need their own context). Spring starts them on first use; the
    // Testcontainers "Ryuk" helper removes them when the test JVM exits.
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");

    static final ElasticsearchContainer ELASTICSEARCH =
            new ElasticsearchContainer("docker.elastic.co/elasticsearch/elasticsearch:8.19.25")
                    .withEnv("xpack.security.enabled", "false")
                    .withEnv("ES_JAVA_OPTS", "-Xms512m -Xmx512m")
                    // Same as Compose: a missing "cves" index is never auto-created with a guessed mapping.
                    .withEnv("action.auto_create_index", "-cves,+*");

    static final KafkaContainer KAFKA = new KafkaContainer("apache/kafka:3.9.2");

    @Bean
    @ServiceConnection
    PostgreSQLContainer<?> postgresContainer() {
        return POSTGRES;
    }

    @Bean
    @ServiceConnection
    ElasticsearchContainer elasticsearchContainer() {
        return ELASTICSEARCH;
    }

    @Bean
    @ServiceConnection
    KafkaContainer kafkaContainer() {
        return KAFKA;
    }
}
