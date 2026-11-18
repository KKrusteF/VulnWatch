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
 * not reachable, the exception stops the application, so a broken setup is noticed right away.
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
        initialize();
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
