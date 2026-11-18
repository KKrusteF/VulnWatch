package com.vulnwatch.search;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch.core.BulkRequest;
import co.elastic.clients.elasticsearch.core.BulkResponse;
import com.vulnwatch.cve.CveRepository;
import com.vulnwatch.cve.CveResponse;
import com.vulnwatch.cve.CveService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Collection;
import java.util.List;

/**
 * Copies CVEs from Postgres into Elasticsearch. Documents are always built from the stored row,
 * and the CVE ID is the document ID, so indexing the same CVE again simply overwrites it.
 */
@Component
public class CveSearchIndexer {

    private static final Logger log = LoggerFactory.getLogger(CveSearchIndexer.class);

    private final ElasticsearchClient client;
    private final CveService cveService;
    private final CveRepository cveRepository;
    private final String indexName;
    private final int batchSize;

    public CveSearchIndexer(ElasticsearchClient client, CveService cveService, CveRepository cveRepository,
                            SearchProperties properties) {
        this.client = client;
        this.cveService = cveService;
        this.cveRepository = cveRepository;
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
            throw new UncheckedIOException("Bulk indexing request to Elasticsearch failed", e);
        }
        // A bulk request can succeed as a whole (HTTP 200) while single documents inside it failed,
        // so the result of every item has to be checked.
        if (response.errors()) {
            List<String> failed = response.items().stream()
                    .filter(item -> item.error() != null)
                    .map(item -> item.id() + " (" + item.error().reason() + ")")
                    .toList();
            throw new IllegalStateException("Elasticsearch rejected " + failed.size() + " of "
                    + response.items().size() + " documents: " + failed);
        }
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
