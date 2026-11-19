package com.vulnwatch.events;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

/**
 * Declares the Kafka topics. Spring Boot's KafkaAdmin creates every {@link NewTopic} bean at startup
 * if the topic does not exist yet.
 */
@Configuration
@EnableConfigurationProperties(EventsProperties.class)
public class EventsConfig {

    @Bean
    NewTopic cveEventsTopic(EventsProperties properties) {
        return TopicBuilder.name(properties.topic()).partitions(properties.partitions()).replicas(1).build();
    }

    /** Events the consumer could not process end up here instead of blocking the main topic. */
    @Bean
    NewTopic cveEventsDeadLetterTopic(EventsProperties properties) {
        return TopicBuilder.name(properties.deadLetterTopic()).partitions(properties.partitions()).replicas(1).build();
    }
}
