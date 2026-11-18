package com.vulnwatch.nvd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Runs the NVD sync on a timer. Only created when {@code vulnwatch.nvd.enabled} is true,
 * so tests and offline runs can switch the background sync off.
 */
@Component
@ConditionalOnProperty(prefix = "vulnwatch.nvd", name = "enabled", havingValue = "true", matchIfMissing = true)
public class NvdSyncScheduler {

    private static final Logger log = LoggerFactory.getLogger(NvdSyncScheduler.class);

    private final NvdSyncService syncService;

    public NvdSyncScheduler(NvdSyncService syncService) {
        this.syncService = syncService;
    }

    // fixedDelay: the next run starts poll-interval after the previous one finished, so runs never overlap.
    @Scheduled(initialDelayString = "${vulnwatch.nvd.initial-delay}", fixedDelayString = "${vulnwatch.nvd.poll-interval}")
    public void syncPeriodically() {
        try {
            syncService.sync();
        } catch (Exception e) {
            // Catch everything: an exception escaping here would be logged by Spring, but catching it
            // keeps the message clear. The next run retries from the last saved cursor.
            log.error("NVD sync failed; will try again in the next run", e);
        }
    }
}
