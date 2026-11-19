package com.vulnwatch.search;

import com.vulnwatch.cve.CveRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Runs once after startup: creates the index if needed and rebuilds it from Postgres when it holds
 * fewer documents than the database (for example after the index was deleted). If Elasticsearch is
 * unreachable, the application still starts: the API and the NVD sync only need Postgres, and the
 * indexer recreates a missing index when it handles the next event.
 */
@Component
public class SearchIndexInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SearchIndexInitializer.class);

    private final CveIndexManager indexManager;
    private final CveSearchIndexer indexer;
    private final CveRepository cveRepository;

    public SearchIndexInitializer(CveIndexManager indexManager, CveSearchIndexer indexer,
                                  CveRepository cveRepository) {
        this.indexManager = indexManager;
        this.indexer = indexer;
        this.cveRepository = cveRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            initialize();
        } catch (SearchUnavailableException e) {
            // Any other exception still stops startup: that would be a bug, not a temporary outage.
            log.warn("Search is unavailable ({}); starting without it. The index will be checked again "
                    + "when the first event is indexed.", e.getMessage());
        }
    }

    /** Creates the index if needed and fills it when it is behind Postgres. */
    public void initialize() {
        boolean created = indexManager.ensureIndexExists();
        long inIndex = indexManager.documentCount();
        long inDatabase = cveRepository.count();
        log.info("Search index '{}' {}: {} documents, {} CVEs in Postgres", indexManager.indexName(),
                created ? "created" : "already exists", inIndex, inDatabase);
        if (inIndex < inDatabase) {
            long indexed = indexer.reindexAll();
            log.info("Rebuilt search index '{}' from Postgres: {} CVEs indexed",
                    indexManager.indexName(), indexed);
        }
    }
}
