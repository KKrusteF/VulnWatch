package com.vulnwatch.search;

import co.elastic.clients.elasticsearch._types.ElasticsearchException;
import co.elastic.clients.elasticsearch._types.mapping.DynamicMapping;
import co.elastic.clients.elasticsearch._types.mapping.Property;
import co.elastic.clients.elasticsearch._types.mapping.TypeMapping;
import com.vulnwatch.AbstractIntegrationTest;
import com.vulnwatch.cve.Severity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.io.StringReader;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests the index itself: the explicit mapping, idempotent indexing and rebuilding from Postgres.
 * The reindex batch size is set to 2 so a rebuild of a few CVEs needs several batches.
 */
@TestPropertySource(properties = "vulnwatch.search.reindex-batch-size=2")
class SearchIndexTest extends AbstractIntegrationTest {

    @Autowired
    SearchIndexInitializer initializer;

    @Autowired
    JdbcTemplate jdbc;

    @Test
    void indexUsesTheExplicitStrictMapping() throws IOException {
        TypeMapping mapping = elasticsearchClient.indices()
                .getMapping(g -> g.index(indexManager.indexName()))
                .result().get(indexManager.indexName()).mappings();
        Map<String, Property> properties = mapping.properties();

        assertThat(mapping.dynamic()).isEqualTo(DynamicMapping.Strict);
        assertThat(properties.get("description").isText()).isTrue();
        assertThat(properties.get("description").text().analyzer()).isEqualTo("english");
        assertThat(properties.get("severity").isKeyword()).isTrue();
        assertThat(properties.get("vendors").isKeyword()).isTrue();
        assertThat(properties.get("id").isKeyword()).isTrue();
        assertThat(properties.get("publishedAt").isDate()).isTrue();
    }

    @Test
    void indexingTheSameCveTwiceKeepsOneDocumentWithTheLatestContent() throws IOException {
        saveCve("CVE-2026-0001", "First description", Severity.HIGH, "2026-01-10T10:00:00Z");
        indexAndRefresh("CVE-2026-0001");
        jdbc.update("update cve set description = 'Second description' where cve_id = 'CVE-2026-0001'");

        indexAndRefresh("CVE-2026-0001");

        assertThat(indexManager.documentCount()).isEqualTo(1);
        CveDocument stored = elasticsearchClient
                .get(g -> g.index(indexManager.indexName()).id("CVE-2026-0001"), CveDocument.class)
                .source();
        assertThat(stored).isNotNull();
        assertThat(stored.description()).isEqualTo("Second description");
        assertThat(stored.publishedAt()).hasToString("2026-01-10T10:00:00Z");
    }

    @Test
    void strictMappingRejectsUnknownFields() {
        String json = """
                {"id": "CVE-2026-0001", "description": "x", "notInTheMapping": "y"}""";

        assertThatThrownBy(() -> elasticsearchClient.index(i -> i
                .index(indexManager.indexName())
                .id("CVE-2026-0001")
                .withJson(new StringReader(json))))
                .isInstanceOf(ElasticsearchException.class)
                .hasMessageContaining("strict_dynamic_mapping_exception");
    }

    @Test
    void reindexAllIndexesEveryRowInSeveralBatches() {
        for (int i = 1; i <= 5; i++) {
            saveCve("CVE-2026-000" + i, Severity.MEDIUM, "2026-01-0" + i + "T10:00:00Z");
        }

        long indexed = searchIndexer.reindexAll();
        indexManager.refresh();

        assertThat(indexed).isEqualTo(5);
        assertThat(indexManager.documentCount()).isEqualTo(5);
    }

    @Test
    void initializerRebuildsAnEmptiedIndexFromPostgres() throws IOException {
        saveCve("CVE-2026-0001", Severity.HIGH, "2026-01-01T10:00:00Z");
        saveCve("CVE-2026-0002", Severity.LOW, "2026-01-02T10:00:00Z");
        saveCve("CVE-2026-0003", Severity.LOW, "2026-01-03T10:00:00Z");
        indexAndRefresh("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003");
        elasticsearchClient.deleteByQuery(d -> d.index(indexManager.indexName())
                .query(q -> q.matchAll(m -> m)).refresh(true));
        assertThat(indexManager.documentCount()).isZero();

        initializer.initialize();
        indexManager.refresh();

        assertThat(indexManager.documentCount()).isEqualTo(cveRepository.count()).isEqualTo(3);
    }

    @Test
    void initializerRecreatesADeletedIndex() throws IOException {
        saveCve("CVE-2026-0001", Severity.HIGH, "2026-01-01T10:00:00Z");
        elasticsearchClient.indices().delete(d -> d.index(indexManager.indexName()));

        initializer.initialize();
        indexManager.refresh();

        assertThat(elasticsearchClient.indices().exists(e -> e.index(indexManager.indexName())).value()).isTrue();
        assertThat(indexManager.documentCount()).isEqualTo(1);
    }
}
