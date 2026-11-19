package com.vulnwatch.search;

import com.vulnwatch.events.CveEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Consumes CVE events from Kafka and indexes the CVE's current row from Postgres into Elasticsearch.
 * Repeated or out-of-order events are harmless: each one just copies the latest stored version.
 */
@Component
public class CveEventListener {

    private static final Logger log = LoggerFactory.getLogger(CveEventListener.class);

    private final CveSearchIndexer indexer;

    public CveEventListener(CveSearchIndexer indexer) {
        this.indexer = indexer;
    }

    @KafkaListener(topics = "${vulnwatch.events.topic}")
    public void onEvent(CveEvent event) {
        log.debug("Indexing {} after {} event", event.cveId(), event.type());
        indexer.indexByIds(List.of(event.cveId()));
    }
}
