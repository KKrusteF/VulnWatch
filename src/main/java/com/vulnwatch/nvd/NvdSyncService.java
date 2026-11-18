package com.vulnwatch.nvd;

import com.vulnwatch.cve.CveData;
import com.vulnwatch.cve.CveUpsertService;
import com.vulnwatch.cve.UpsertResult;
import com.vulnwatch.search.CveSearchIndexer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Pulls every CVE modified since the last successful sync from NVD and stores it.
 * Long periods are split into windows NVD accepts, and progress is saved after each window.
 */
@Service
public class NvdSyncService {

    static final String SOURCE = "nvd-cve";

    /** NVD rejects lastModified ranges longer than 120 days. */
    static final Duration MAX_WINDOW = Duration.ofDays(119);

    private static final Logger log = LoggerFactory.getLogger(NvdSyncService.class);

    private final NvdClient client;
    private final CveUpsertService upsertService;
    private final CveSearchIndexer searchIndexer;
    private final SyncStateRepository syncStateRepository;
    private final NvdProperties properties;
    private final Clock clock;

    public NvdSyncService(NvdClient client, CveUpsertService upsertService, CveSearchIndexer searchIndexer,
                          SyncStateRepository syncStateRepository, NvdProperties properties, Clock clock) {
        this.client = client;
        this.upsertService = upsertService;
        this.searchIndexer = searchIndexer;
        this.syncStateRepository = syncStateRepository;
        this.properties = properties;
        this.clock = clock;
    }

    // Deliberately not @Transactional: a sync makes slow HTTP calls, and a database transaction should
    // never stay open while waiting for them. Each page is committed on its own by CveUpsertService.
    public SyncResult sync() {
        Instant now = clock.instant().truncatedTo(ChronoUnit.MILLIS);
        Instant start = syncStateRepository.findById(SOURCE)
                .map(state -> state.getLastSyncedUntil().minus(properties.overlap()))
                .orElse(now.minus(properties.initialLookback()));

        int fetched = 0;
        UpsertResult totals = UpsertResult.EMPTY;
        Instant from = start;
        while (from.isBefore(now)) {
            Instant to = earliest(from.plus(MAX_WINDOW), now);
            int startIndex = 0;
            while (true) {
                NvdPage page = client.fetchModified(from, to, startIndex);
                List<CveData> cves = page.vulnerabilities().stream()
                        .map(vulnerability -> NvdCveMapper.toCveData(vulnerability.cve()))
                        .toList();
                if (cves.isEmpty()) {
                    if (startIndex < page.totalResults()) {
                        // NVD promised more results than it delivered. Fail without saving the cursor,
                        // so the next run fetches this window again instead of silently skipping CVEs.
                        throw new IllegalStateException("NVD returned an empty page at startIndex " + startIndex
                                + " although totalResults is " + page.totalResults());
                    }
                    break;
                }
                totals = totals.plus(upsertService.upsertAll(cves));
                // Index every CVE on the page, changed or not. If indexing failed on an earlier run, the
                // cursor did not move, so this window is fetched again and its rows are now "unchanged" in
                // Postgres; indexing all of them is what repairs the index. Repeating it is harmless because
                // the document ID is the CVE ID. An exception here stops the sync before the cursor moves.
                searchIndexer.indexByIds(cves.stream().map(CveData::id).toList());
                fetched += cves.size();
                startIndex += cves.size();
                if (startIndex >= page.totalResults()) {
                    break;
                }
            }
            saveCursor(to);
            from = to;
        }

        SyncResult result = new SyncResult(start, now, fetched, totals.created(), totals.updated(),
                totals.unchanged());
        log.info("NVD sync finished: window {} to {}, fetched {}, created {}, updated {}, unchanged {}",
                result.from(), result.to(), result.fetched(), result.created(), result.updated(),
                result.unchanged());
        return result;
    }

    /** Remembers that everything modified up to {@code syncedUntil} is stored. */
    private void saveCursor(Instant syncedUntil) {
        SyncState state = syncStateRepository.findById(SOURCE)
                .orElseGet(() -> new SyncState(SOURCE, syncedUntil, clock.instant()));
        state.advanceTo(syncedUntil, clock.instant());
        syncStateRepository.save(state);
    }

    private static Instant earliest(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }
}
