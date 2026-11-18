package com.vulnwatch.search;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * The {@code vulnwatch.search.*} settings: which Elasticsearch index to use and how many CVEs
 * to send per bulk request when the index is rebuilt.
 */
@ConfigurationProperties("vulnwatch.search")
@Validated
public record SearchProperties(
        @NotBlank String indexName,
        @Min(1) @Max(10_000) int reindexBatchSize) {
}
