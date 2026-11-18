package com.vulnwatch.search;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * Creates the CVE index with the explicit mapping from {@code elasticsearch/cve-index.json}
 * and answers simple questions about it.
 */
@Component
public class CveIndexManager {

    private static final String MAPPING_FILE = "elasticsearch/cve-index.json";

    private final ElasticsearchClient client;
    private final String indexName;

    public CveIndexManager(ElasticsearchClient client, SearchProperties properties) {
        this.client = client;
        this.indexName = properties.indexName();
    }

    public String indexName() {
        return indexName;
    }

    /** Creates the index if it does not exist yet. Returns true when it was created now. */
    public boolean ensureIndexExists() {
        try {
            if (client.indices().exists(e -> e.index(indexName)).value()) {
                return false;
            }
            try (InputStream mapping = new ClassPathResource(MAPPING_FILE).getInputStream()) {
                // withJson reads the settings and mappings straight from the JSON file.
                client.indices().create(c -> c.index(indexName).withJson(mapping));
            }
            return true;
        } catch (IOException e) {
            throw new UncheckedIOException("Could not create Elasticsearch index " + indexName, e);
        }
    }

    /** Number of documents in the index (counts only documents visible after the last refresh). */
    public long documentCount() {
        try {
            return client.count(c -> c.index(indexName)).count();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Makes everything indexed so far visible to search right away. Only tests call this:
     * in normal operation Elasticsearch refreshes on its own every second.
     */
    public void refresh() {
        try {
            client.indices().refresh(r -> r.index(indexName));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
