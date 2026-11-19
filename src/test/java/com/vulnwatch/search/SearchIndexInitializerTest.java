package com.vulnwatch.search;

import com.vulnwatch.cve.CveRepository;
import org.junit.jupiter.api.Test;

import java.net.ConnectException;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Plain unit test (no Spring, no containers): startup survives Elasticsearch being down, but not other errors.
 */
class SearchIndexInitializerTest {

    private final CveIndexManager indexManager = mock(CveIndexManager.class);
    private final CveSearchIndexer indexer = mock(CveSearchIndexer.class);
    private final CveRepository cveRepository = mock(CveRepository.class);
    private final SearchIndexInitializer initializer = new SearchIndexInitializer(indexManager, indexer, cveRepository);

    @Test
    void startupContinuesWhenElasticsearchIsUnavailable() {
        when(indexManager.ensureIndexExists()).thenThrow(
                SearchUnavailableException.from("Creating index cves", new ConnectException("Connection refused")));

        assertThatCode(() -> initializer.run(null)).doesNotThrowAnyException();
        verifyNoInteractions(indexer);
    }

    @Test
    void otherErrorsStillStopStartup() {
        when(indexManager.ensureIndexExists()).thenThrow(new IllegalStateException("broken mapping file"));

        assertThatThrownBy(() -> initializer.run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("broken mapping file");
    }
}
