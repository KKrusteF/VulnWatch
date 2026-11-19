package com.vulnwatch.search;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.ElasticsearchException;
import co.elastic.clients.elasticsearch.core.BulkRequest;
import co.elastic.clients.elasticsearch.core.BulkResponse;
import com.vulnwatch.cve.CveRepository;
import com.vulnwatch.cve.CveResponse;
import com.vulnwatch.cve.CveService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

/**
 * Copies CVEs from Postgres into Elasticsearch. Documents are always built from the stored row,
 * and the CVE ID is the document ID, so indexing the same CVE again simply overwrites it.
 */
@Component
public class CveSearchIndexer {

    private static final Logger log = LoggerFactory.getLogger(CveSearchIndexer.class);

    private static final String INDEX_NOT_FOUND = "index_not_found_exception";

    private final ElasticsearchClient client;
    private final CveService cveService;
    private final CveRepository cveRepository;
    private final CveIndexManager indexManager;
    private final String indexName;
    private final int batchSize;

    public CveSearchIndexer(ElasticsearchClient client, CveService cveService, CveRepository cveRepository,
                            CveIndexManager indexManager, SearchProperties properties) {
        this.client = client;
        this.cveService = cveService;
        this.cveRepository = cveRepository;
        this.indexManager = indexManager;
        this.indexName = properties.indexName();
        this.batchSize = properties.reindexBatchSize();
    }

    /** Indexes the current Postgres version of these CVEs with one bulk request. */
    public void indexByIds(Collection<String> ids) {
        if (ids.isEmpty()) {
            return;
        }
        List<CveResponse> cves = cveService.getByIds(ids);
        if (cves.isEmpty()) {
            return;
        }
        BulkRequest.Builder bulk = new BulkRequest.Builder();
        for (CveResponse cve : cves) {
            bulk.operations(op -> op.index(i -> i
                    .index(indexName)
                    .id(cve.id())
                    .document(CveDocument.from(cve))));
        }
        BulkResponse response;
        try {
            response = client.bulk(bulk.build());
        } catch (IOException e) {
            throw SearchUnavailableException.from("Bulk indexing", e);
        } catch (ElasticsearchException e) {
            if (INDEX_NOT_FOUND.equals(e.error().type())) {
                throw recreateMissingIndex();
            }
            throw SearchUnavailableException.classify("Bulk indexing", e);
        }
        // A bulk request can succeed as a whole (HTTP 200) while single documents inside it failed,
        // so the result of every item has to be checked. Such a rejection is permanent (for example a
        // document that does not fit the mapping), so it is not a SearchUnavailableException.
        if (response.errors()) {
            if (response.items().stream().anyMatch(item -> item.error() != null
                    && INDEX_NOT_FOUND.equals(item.error().type()))) {
                throw recreateMissingIndex();
            }
            List<String> failed = response.items().stream()
                    .filter(item -> item.error() != null)
                    .map(item -> item.id() + " (" + item.error().reason() + ")")
                    .toList();
            throw new IllegalStateException("Elasticsearch rejected " + failed.size() + " of "
                    + response.items().size() + " documents: " + failed);
        }
    }

    /**
     * The index was deleted while the app was running. Elasticsearch is configured not to auto-create it
     * (it would guess the mapping), so the bulk request failed. Recreate it from cve-index.json and report
     * a temporary failure: the Kafka error handler retries the event, and the retry finds a correctly
     * mapped index. Other CVEs are put back by the startup rebuild, which sees the index is behind.
     */
    private SearchUnavailableException recreateMissingIndex() {
        indexManager.ensureIndexExists();
        log.warn("Search index '{}' was missing and has been recreated", indexName);
        return new SearchUnavailableException("search index was missing and has been recreated; retrying", null);
    }

    /** Rebuilds the index from Postgres in batches. Returns the number of CVEs indexed. */
    public long reindexAll() {
        long indexed = 0;
        String lastId = "";
        while (true) {
            List<String> ids = cveRepository.findIdsAfter(lastId, batchSize);
            if (ids.isEmpty()) {
                break;
            }
            indexByIds(ids);
            indexed += ids.size();
            lastId = ids.getLast();
            log.info("Reindexed {} CVEs so far (up to {})", indexed, lastId);
        }
        return indexed;
    }
}
