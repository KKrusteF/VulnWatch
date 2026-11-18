package com.vulnwatch;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import com.vulnwatch.cve.Cve;
import com.vulnwatch.cve.CveRepository;
import com.vulnwatch.cve.Severity;
import com.vulnwatch.search.CveIndexManager;
import com.vulnwatch.search.CveSearchIndexer;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Base class for tests that start the whole application against real Postgres and Elasticsearch
 * containers. Spring caches the application context, so all subclasses with the same setup share one app.
 * The scheduled NVD sync is switched off so tests never call the real NVD.
 */
@SpringBootTest(properties = "vulnwatch.nvd.enabled=false")
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

    @BeforeEach
    void cleanDatabaseAndIndex() throws IOException {
        cveRepository.deleteAll();
        indexManager.ensureIndexExists();
        // delete_by_query works on what was visible at the last refresh; a document indexed after that
        // (for example by a sync in the previous test) would make it fail with a version conflict.
        indexManager.refresh();
        elasticsearchClient.deleteByQuery(d -> d
                .index(indexManager.indexName())
                .query(q -> q.matchAll(m -> m))
                .refresh(true));
        indexManager.refresh();
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
}
