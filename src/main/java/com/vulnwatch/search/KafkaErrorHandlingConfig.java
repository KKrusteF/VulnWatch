package com.vulnwatch.search;

import com.vulnwatch.events.CveEvent;
import com.vulnwatch.events.EventsProperties;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.Serializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.support.serializer.DelegatingByTypeSerializer;
import org.springframework.kafka.support.serializer.JsonSerializer;
import org.springframework.util.backoff.ExponentialBackOff;
import org.springframework.util.backoff.FixedBackOff;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Decides what the Kafka consumer does when indexing an event fails. Spring Boot attaches the
 * {@code DefaultErrorHandler} bean below to every {@code @KafkaListener} automatically.
 */
@Configuration
public class KafkaErrorHandlingConfig {

    private static final Logger log = LoggerFactory.getLogger(KafkaErrorHandlingConfig.class);

    /**
     * Elasticsearch unavailable: retry the same event with exponential backoff and no attempt limit, so
     * the consumer waits (and lag grows) instead of dropping events. Any other error: a few quick retries,
     * then the event goes to the dead letter topic. Messages that are not valid JSON go there immediately.
     */
    @Bean
    DefaultErrorHandler kafkaErrorHandler(ProducerFactory<?, ?> producerFactory, EventsProperties properties) {
        EventsProperties.ListenerRetry retry = properties.listenerRetry();
        DeadLetterPublishingRecoverer recoverer = new DeadLetterPublishingRecoverer(
                deadLetterTemplate(producerFactory),
                // Same partition number in the dead letter topic, which has as many partitions as the main one.
                (record, exception) -> new TopicPartition(properties.deadLetterTopic(), record.partition()));

        DefaultErrorHandler handler = new DefaultErrorHandler(recoverer,
                new FixedBackOff(retry.failureInterval().toMillis(), retry.failureRetries()));
        handler.setBackOffFunction((record, exception) -> {
            if (!causedBySearchUnavailable(exception)) {
                return null; // use the default back-off above
            }
            ExponentialBackOff backOff = new ExponentialBackOff(retry.unavailableInitialBackoff().toMillis(), 2.0);
            backOff.setMaxInterval(retry.unavailableMaxBackoff().toMillis());
            // ExponentialBackOff never gives up by default (no attempt or elapsed-time limit).
            return backOff;
        });
        handler.setRetryListeners((record, exception, attempt) -> log.warn(
                "Indexing event for {} failed (attempt {}): {}", record.key(), attempt, rootMessage(exception)));
        return handler;
    }

    /**
     * A separate template for the dead letter topic. A message that could not be parsed reaches the
     * recoverer as its original bytes, so byte[] values are written unchanged and events as JSON.
     * It is not a bean on purpose: a second KafkaTemplate bean would replace the one Spring Boot creates.
     */
    private static KafkaTemplate<String, Object> deadLetterTemplate(ProducerFactory<?, ?> producerFactory) {
        Map<Class<?>, Serializer<?>> serializers = new LinkedHashMap<>();
        serializers.put(byte[].class, new ByteArraySerializer());
        serializers.put(CveEvent.class, new JsonSerializer<CveEvent>().noTypeInfo());
        // Reuse Boot's producer settings (including the broker address), minus the JSON serializer settings:
        // the serializers here are configured in code, and JsonSerializer refuses to get both.
        Map<String, Object> config = new LinkedHashMap<>(producerFactory.getConfigurationProperties());
        config.keySet().removeIf(key -> key.startsWith("spring.json."));
        return new KafkaTemplate<>(new DefaultKafkaProducerFactory<String, Object>(
                config, new StringSerializer(), new DelegatingByTypeSerializer(serializers)));
    }

    private static boolean causedBySearchUnavailable(Throwable exception) {
        for (Throwable t = exception; t != null; t = t.getCause()) {
            if (t instanceof SearchUnavailableException) {
                return true;
            }
        }
        return false;
    }

    private static String rootMessage(Throwable exception) {
        Throwable root = exception;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        return root.getClass().getSimpleName() + ": " + root.getMessage();
    }
}
