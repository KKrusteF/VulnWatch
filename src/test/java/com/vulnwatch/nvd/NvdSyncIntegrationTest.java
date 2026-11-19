package com.vulnwatch.nvd;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.vulnwatch.AbstractIntegrationTest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import com.vulnwatch.search.CveSearchIndexer;
import com.vulnwatch.search.SearchUnavailableException;
import org.springframework.web.client.HttpServerErrorException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.contains;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Runs the real sync (client, mapper, upsert, cursor) against a fake NVD (WireMock) and a real
 * Postgres container. The clock is a Mockito mock, so each test decides what "now" is.
 * The indexer is a spy, so a test can make Elasticsearch look unavailable.
 */
class NvdSyncIntegrationTest extends AbstractIntegrationTest {

    private static final String PATH = "/rest/json/cves/2.0";
    private static final Instant NOW = Instant.parse("2026-11-18T12:00:00Z");

    // Started once for this class, before Spring reads the base URL below.
    private static final WireMockServer nvd = new WireMockServer(wireMockConfig().dynamicPort());

    static {
        nvd.start();
    }

    @DynamicPropertySource
    static void nvdProperties(DynamicPropertyRegistry registry) {
        registry.add("vulnwatch.nvd.base-url", () -> nvd.baseUrl() + PATH);
        registry.add("vulnwatch.nvd.results-per-page", () -> 2);
        registry.add("vulnwatch.nvd.request-interval", () -> "0s");
        registry.add("vulnwatch.nvd.retry.max-attempts", () -> 3);
        registry.add("vulnwatch.nvd.retry.initial-backoff", () -> "1ms");
        registry.add("vulnwatch.nvd.retry.max-backoff", () -> "5ms");
    }

    @AfterAll
    static void stopNvd() {
        nvd.stop();
    }

    @MockitoBean
    Clock clock;

    // A real indexer that a test can make fail on purpose.
    @MockitoSpyBean
    CveSearchIndexer spiedIndexer;

    @Autowired
    NvdSyncService syncService;

    @Autowired
    SyncStateRepository syncStateRepository;

    @Autowired
    JdbcTemplate jdbc;

    @BeforeEach
    void reset() {
        nvd.resetAll();
        syncStateRepository.deleteAll();
        setNow(NOW);
    }

    @Test
    void firstSyncLooksBackInitialLookbackAndStoresCvesAndCursor() throws Exception {
        stubPage(0, 2, cve("CVE-2026-0001", "2026-11-17T10:00:00.000", "HIGH", "apache", "cisco"),
                cve("CVE-2026-0002", "2026-11-17T11:00:00.000", "LOW"));

        SyncResult result = syncService.sync();

        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH))
                .withQueryParam("lastModStartDate", equalTo("2026-11-11T12:00:00.000Z"))
                .withQueryParam("lastModEndDate", equalTo("2026-11-18T12:00:00.000Z"))
                .withQueryParam("startIndex", equalTo("0"))
                .withQueryParam("resultsPerPage", equalTo("2")));
        assertThat(result.fetched()).isEqualTo(2);
        assertThat(result.created()).isEqualTo(2);
        assertThat(cveRepository.count()).isEqualTo(2);
        mockMvc.perform(get("/api/cves/CVE-2026-0001"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.severity").value("HIGH"))
                .andExpect(jsonPath("$.vendors", contains("apache", "cisco")));
        assertThat(cursor()).isEqualTo(NOW);
    }

    @Test
    void followsPagesUntilTotalResults() {
        stubPage(0, 3, cve("CVE-2026-0001", "2026-11-17T10:00:00.000", "HIGH"),
                cve("CVE-2026-0002", "2026-11-17T11:00:00.000", "LOW"));
        stubPage(2, 3, cve("CVE-2026-0003", "2026-11-17T12:00:00.000", "MEDIUM"));

        SyncResult result = syncService.sync();

        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH)).withQueryParam("startIndex", equalTo("0")));
        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH)).withQueryParam("startIndex", equalTo("2")));
        nvd.verify(2, getRequestedFor(urlPathEqualTo(PATH)));
        assertThat(result.fetched()).isEqualTo(3);
        assertThat(result.created()).isEqualTo(3);
        assertThat(cveRepository.count()).isEqualTo(3);
    }

    @Test
    void runningTheSameSyncTwiceCreatesNoDuplicates() {
        stubPage(0, 3, cve("CVE-2026-0001", "2026-11-17T10:00:00.000", "HIGH", "apache"),
                cve("CVE-2026-0002", "2026-11-17T11:00:00.000", "LOW"));
        stubPage(2, 3, cve("CVE-2026-0003", "2026-11-17T12:00:00.000", "MEDIUM"));

        syncService.sync();
        SyncResult second = syncService.sync();

        assertThat(second.created()).isZero();
        assertThat(second.updated()).isZero();
        assertThat(second.unchanged()).isEqualTo(3);
        assertThat(cveRepository.count()).isEqualTo(3);
        assertThat(vendorRows("CVE-2026-0001")).isEqualTo(1);
    }

    @Test
    void newerVersionUpdatesTheStoredCveInPlace() throws Exception {
        stubPage(0, 1, cve("CVE-2026-0001", "2026-11-17T10:00:00.000", "HIGH", "apache", "cisco"));
        syncService.sync();

        nvd.resetAll();
        stubPage(0, 1, cve("CVE-2026-0001", "2026-11-18T13:00:00.000", "CRITICAL", "cisco", "oracle"));
        setNow(NOW.plus(Duration.ofHours(2)));
        SyncResult result = syncService.sync();

        assertThat(result.updated()).isEqualTo(1);
        assertThat(result.created()).isZero();
        assertThat(cveRepository.count()).isEqualTo(1);
        assertThat(vendorRows("CVE-2026-0001")).isEqualTo(2);
        mockMvc.perform(get("/api/cves/CVE-2026-0001"))
                .andExpect(jsonPath("$.severity").value("CRITICAL"))
                .andExpect(jsonPath("$.lastModifiedAt").value("2026-11-18T13:00:00Z"))
                .andExpect(jsonPath("$.vendors", contains("cisco", "oracle")));
    }

    @Test
    void olderVersionDoesNotOverwriteNewerData() throws Exception {
        stubPage(0, 1, cve("CVE-2026-0001", "2026-11-17T10:00:00.000", "CRITICAL", "apache"));
        syncService.sync();

        nvd.resetAll();
        stubPage(0, 1, cve("CVE-2026-0001", "2026-11-16T10:00:00.000", "LOW", "oracle"));
        SyncResult result = syncService.sync();

        assertThat(result.unchanged()).isEqualTo(1);
        assertThat(result.updated()).isZero();
        mockMvc.perform(get("/api/cves/CVE-2026-0001"))
                .andExpect(jsonPath("$.severity").value("CRITICAL"))
                .andExpect(jsonPath("$.vendors", contains("apache")));
    }

    @Test
    void nextSyncStartsAtCursorMinusOverlap() {
        stubPage(0, 0);
        syncService.sync();
        Instant later = NOW.plus(Duration.ofHours(2));
        setNow(later);

        SyncResult second = syncService.sync();

        assertThat(second.from()).isEqualTo(NOW.minus(Duration.ofMinutes(5)));
        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH))
                .withQueryParam("lastModStartDate", equalTo("2026-11-18T11:55:00.000Z"))
                .withQueryParam("lastModEndDate", equalTo("2026-11-18T14:00:00.000Z")));
        assertThat(cursor()).isEqualTo(later);
    }

    @Test
    void longGapIsSplitIntoWindowsNvdAccepts() {
        syncStateRepository.save(new SyncState(NvdSyncService.SOURCE, NOW.minus(Duration.ofDays(200)), NOW));
        stubPage(0, 0);

        syncService.sync();

        // 200 days + 5 minutes of overlap: one 119-day window, then the rest up to now.
        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH))
                .withQueryParam("lastModStartDate", equalTo("2026-05-02T11:55:00.000Z"))
                .withQueryParam("lastModEndDate", equalTo("2026-08-29T11:55:00.000Z")));
        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH))
                .withQueryParam("lastModStartDate", equalTo("2026-08-29T11:55:00.000Z"))
                .withQueryParam("lastModEndDate", equalTo("2026-11-18T12:00:00.000Z")));
        nvd.verify(2, getRequestedFor(urlPathEqualTo(PATH)));
        assertThat(cursor()).isEqualTo(NOW);
    }

    @Test
    void failedSyncKeepsCursorSoTheNextSyncStartsFromTheSamePoint() {
        stubPage(0, 0);
        syncService.sync();

        nvd.resetAll();
        nvd.stubFor(WireMock.get(urlPathEqualTo(PATH))
                .willReturn(aResponse().withStatus(500)));
        setNow(NOW.plus(Duration.ofHours(2)));

        assertThatThrownBy(() -> syncService.sync()).isInstanceOf(HttpServerErrorException.class);
        nvd.verify(3, getRequestedFor(urlPathEqualTo(PATH)));
        assertThat(cursor()).isEqualTo(NOW);

        nvd.resetAll();
        stubPage(0, 0);
        setNow(NOW.plus(Duration.ofHours(4)));
        syncService.sync();

        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH))
                .withQueryParam("lastModStartDate", equalTo("2026-11-18T11:55:00.000Z")));
        assertThat(cursor()).isEqualTo(NOW.plus(Duration.ofHours(4)));
    }

    @Test
    void pagesStoredBeforeAFailureStayStored() {
        stubPage(0, 3, cve("CVE-2026-0001", "2026-11-17T10:00:00.000", "HIGH"),
                cve("CVE-2026-0002", "2026-11-17T11:00:00.000", "LOW"));
        nvd.stubFor(WireMock.get(urlPathEqualTo(PATH))
                .withQueryParam("startIndex", equalTo("2"))
                .willReturn(aResponse().withStatus(500)));

        assertThatThrownBy(() -> syncService.sync()).isInstanceOf(HttpServerErrorException.class);

        assertThat(cveRepository.count()).isEqualTo(2);
        assertThat(syncStateRepository.findById(NvdSyncService.SOURCE)).isEmpty();
    }

    @Test
    void syncWritesOneOutboxRowPerCreatedOrUpdatedCveAndNoneForUnchanged() {
        stubPage(0, 2, cve("CVE-2026-0001", "2026-11-17T10:00:00.000", "HIGH"),
                cve("CVE-2026-0002", "2026-11-17T11:00:00.000", "LOW"));

        syncService.sync();
        assertThat(outboxRows()).containsExactly("CVE-2026-0001 CREATED", "CVE-2026-0002 CREATED");

        syncService.sync(); // same data again: both unchanged
        assertThat(outboxRows()).hasSize(2);

        nvd.resetAll();
        stubPage(0, 1, cve("CVE-2026-0002", "2026-11-18T11:30:00.000", "CRITICAL"));
        syncService.sync();
        assertThat(outboxRows()).containsExactly("CVE-2026-0001 CREATED", "CVE-2026-0002 CREATED",
                "CVE-2026-0002 UPDATED");
    }

    @Test
    void publishedEventsMakeSyncedCvesSearchable() throws Exception {
        startKafkaListener();
        stubPage(0, 2, cve("CVE-2026-0001", "2026-11-17T10:00:00.000", "HIGH", "apache"),
                cve("CVE-2026-0002", "2026-11-17T11:00:00.000", "LOW"));

        syncService.sync();
        assertThat(outboxPublisher.publishPending()).isEqualTo(2);

        await().atMost(Duration.ofSeconds(30)).untilAsserted(() -> {
            indexManager.refresh();
            mockMvc.perform(get("/api/cves/search").param("q", "description"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalItems").value(2));
        });
        mockMvc.perform(get("/api/cves/search").param("q", "description").param("vendor", "apache"))
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2026-0001")));
    }

    @Test
    void syncSucceedsAndAdvancesTheCursorWhileElasticsearchIsDown() {
        stubPage(0, 2, cve("CVE-2026-0001", "2026-11-17T10:00:00.000", "HIGH"),
                cve("CVE-2026-0002", "2026-11-17T11:00:00.000", "LOW"));
        doThrow(new SearchUnavailableException("Elasticsearch is down (test)", null))
                .when(spiedIndexer).indexByIds(anyCollection());

        SyncResult result = syncService.sync();

        assertThat(result.created()).isEqualTo(2);
        assertThat(cursor()).isEqualTo(NOW);
        assertThat(cveRepository.count()).isEqualTo(2);
        assertThat(outboxRows()).hasSize(2);
        // The sync no longer talks to Elasticsearch at all; indexing happens later through Kafka.
        verify(spiedIndexer, never()).indexByIds(anyCollection());
    }

    private List<String> outboxRows() {
        return jdbc.queryForList("select cve_id || ' ' || event_type from cve_outbox order by id", String.class);
    }

    private void setNow(Instant now) {
        when(clock.instant()).thenReturn(now);
    }

    private Instant cursor() {
        return syncStateRepository.findById(NvdSyncService.SOURCE).orElseThrow().getLastSyncedUntil();
    }

    private int vendorRows(String cveId) {
        return jdbc.queryForObject("select count(*) from cve_vendor where cve_id = ?", Integer.class, cveId);
    }

    /** Makes the fake NVD answer requests with this startIndex with the given CVEs. */
    private void stubPage(int startIndex, int totalResults, String... cves) {
        String body = """
                {"resultsPerPage": %d, "startIndex": %d, "totalResults": %d, "format": "NVD_CVE",
                 "version": "2.0", "vulnerabilities": [%s]}"""
                .formatted(cves.length, startIndex, totalResults, String.join(",", cves));
        nvd.stubFor(WireMock.get(urlPathEqualTo(PATH))
                .withQueryParam("startIndex", equalTo(String.valueOf(startIndex)))
                .willReturn(okJson(body)));
    }

    /** One CVE in NVD's JSON format, with a v3.1 score and one vulnerable CPE per vendor. */
    private static String cve(String id, String lastModified, String severity, String... vendors) {
        String cpes = Arrays.stream(vendors)
                .map(v -> "{\"vulnerable\": true, \"criteria\": \"cpe:2.3:a:%s:product:*:*:*:*:*:*:*:*\"}".formatted(v))
                .collect(Collectors.joining(","));
        return """
                {"cve": {
                  "id": "%s",
                  "published": "2026-11-01T00:00:00.000",
                  "lastModified": "%s",
                  "vulnStatus": "Analyzed",
                  "descriptions": [{"lang": "en", "value": "Description of %s"}],
                  "metrics": {"cvssMetricV31": [{"type": "Primary",
                    "cvssData": {"version": "3.1", "baseScore": 5.0, "baseSeverity": "%s"}}]},
                  "configurations": [{"nodes": [{"cpeMatch": [%s]}]}]
                }}""".formatted(id, lastModified, id, severity, cpes);
    }
}
