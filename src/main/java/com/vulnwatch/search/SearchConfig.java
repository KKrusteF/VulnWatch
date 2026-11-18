package com.vulnwatch.search;

import co.elastic.clients.json.JsonpMapper;
import co.elastic.clients.json.jackson.JacksonJsonpMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

/**
 * Settings and beans for the Elasticsearch side. Spring Boot creates the {@code ElasticsearchClient}
 * itself from {@code spring.elasticsearch.uris}; this class only adjusts how it turns objects into JSON.
 */
@Configuration
@EnableConfigurationProperties(SearchProperties.class)
public class SearchConfig {

    /**
     * Boot's default mapper for the Elasticsearch client is a plain Jackson ObjectMapper that does not
     * know java.time types, so writing a CveDocument with an Instant would fail. This bean replaces it
     * with one built like Boot's own ObjectMapper: Instants become ISO-8601 strings such as
     * "2021-12-10T10:15:09.143Z", which the "date" fields in the mapping understand.
     */
    @Bean
    JsonpMapper elasticsearchJsonpMapper(Jackson2ObjectMapperBuilder builder) {
        return new JacksonJsonpMapper(builder.build());
    }
}
