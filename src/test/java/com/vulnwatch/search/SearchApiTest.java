package com.vulnwatch.search;

import com.vulnwatch.AbstractIntegrationTest;
import com.vulnwatch.cve.Severity;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests {@code GET /api/cves/search} end to end: CVEs are stored in Postgres, indexed into a real
 * Elasticsearch container and searched through the HTTP API.
 */
class SearchApiTest extends AbstractIntegrationTest {

    @Test
    void findsCveByWordInDescription() throws Exception {
        saveCve("CVE-2026-0001", "Heap overflow in the PNG decoder", Severity.HIGH, "2026-01-10T10:00:00Z", "libpng");
        saveCve("CVE-2026-0002", "Cross-site scripting in the login form", Severity.MEDIUM, "2026-01-11T10:00:00Z");
        indexAndRefresh("CVE-2026-0001", "CVE-2026-0002");

        mockMvc.perform(get("/api/cves/search").param("q", "decoder"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2026-0001")))
                .andExpect(jsonPath("$.items[0].description").value("Heap overflow in the PNG decoder"))
                .andExpect(jsonPath("$.items[0].severity").value("HIGH"))
                .andExpect(jsonPath("$.items[0].vendors", contains("libpng")))
                .andExpect(jsonPath("$.items[0].publishedAt").value("2026-01-10T10:00:00Z"))
                .andExpect(jsonPath("$.totalItems").value(1));
    }

    @Test
    void englishStemmingMatchesOtherWordForms() throws Exception {
        saveCve("CVE-2026-0001", "Allows remote code execution via crafted input", Severity.CRITICAL,
                "2026-01-10T10:00:00Z");
        indexAndRefresh("CVE-2026-0001");

        mockMvc.perform(get("/api/cves/search").param("q", "executing"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2026-0001")));
    }

    @Test
    void everyWordMustMatch() throws Exception {
        saveCve("CVE-2026-0001", "Buffer overflow in the kernel driver", Severity.HIGH, "2026-01-10T10:00:00Z");
        saveCve("CVE-2026-0002", "Buffer overflow in the web server", Severity.HIGH, "2026-01-11T10:00:00Z");
        indexAndRefresh("CVE-2026-0001", "CVE-2026-0002");

        mockMvc.perform(get("/api/cves/search").param("q", "overflow kernel"))
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2026-0001")));
        mockMvc.perform(get("/api/cves/search").param("q", "overflow"))
                .andExpect(jsonPath("$.items[*].id", containsInAnyOrder("CVE-2026-0001", "CVE-2026-0002")));
    }

    @Test
    void quotedPhraseMatchesOnlyTheExactPhrase() throws Exception {
        saveCve("CVE-2026-0001", "SQL injection in the search page", Severity.HIGH, "2026-01-10T10:00:00Z");
        saveCve("CVE-2026-0002", "Injection of SQL fragments through headers", Severity.HIGH, "2026-01-11T10:00:00Z");
        indexAndRefresh("CVE-2026-0001", "CVE-2026-0002");

        mockMvc.perform(get("/api/cves/search").param("q", "\"sql injection\""))
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2026-0001")));
        mockMvc.perform(get("/api/cves/search").param("q", "sql injection"))
                .andExpect(jsonPath("$.items", hasSize(2)));
    }

    @Test
    void filtersCombineWithTheTextQuery() throws Exception {
        saveCve("CVE-2026-0001", "Remote code execution in router firmware", Severity.CRITICAL,
                "2026-03-10T10:00:00Z", "cisco");
        saveCve("CVE-2026-0002", "Remote code execution in mail server", Severity.HIGH,
                "2026-03-11T10:00:00Z", "cisco");
        saveCve("CVE-2026-0003", "Remote code execution in database", Severity.CRITICAL,
                "2026-03-12T10:00:00Z", "oracle");
        saveCve("CVE-2026-0004", "Remote code execution in old firmware", Severity.CRITICAL,
                "2025-03-10T10:00:00Z", "cisco");
        saveCve("CVE-2026-0005", "Denial of service in router firmware", Severity.CRITICAL,
                "2026-03-10T10:00:00Z", "cisco");
        indexAndRefresh("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005");

        mockMvc.perform(get("/api/cves/search").param("q", "remote execution")
                        .param("severity", "critical")
                        .param("vendor", "CISCO")
                        .param("publishedFrom", "2026-03-01")
                        .param("publishedTo", "2026-03-31"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2026-0001")))
                .andExpect(jsonPath("$.totalItems").value(1));
    }

    @Test
    void dateRangeIncludesBothEndDays() throws Exception {
        saveCve("CVE-2026-0001", "Overflow one", Severity.HIGH, "2026-03-10T00:00:00Z");
        saveCve("CVE-2026-0002", "Overflow two", Severity.HIGH, "2026-03-12T23:59:59Z");
        saveCve("CVE-2026-0003", "Overflow three", Severity.HIGH, "2026-03-13T00:00:00Z");
        saveCve("CVE-2026-0004", "Overflow four", Severity.HIGH, "2026-03-09T23:59:59Z");
        indexAndRefresh("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004");

        mockMvc.perform(get("/api/cves/search").param("q", "overflow")
                        .param("publishedFrom", "2026-03-10")
                        .param("publishedTo", "2026-03-12"))
                .andExpect(jsonPath("$.items[*].id", containsInAnyOrder("CVE-2026-0001", "CVE-2026-0002")));
    }

    @Test
    void documentMatchingTheTextButNotTheFilterIsExcluded() throws Exception {
        saveCve("CVE-2026-0001", "Path traversal in file upload", Severity.LOW, "2026-01-10T10:00:00Z");
        indexAndRefresh("CVE-2026-0001");

        mockMvc.perform(get("/api/cves/search").param("q", "traversal").param("severity", "HIGH"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items", empty()))
                .andExpect(jsonPath("$.totalItems").value(0))
                .andExpect(jsonPath("$.totalPages").value(0));
    }

    @Test
    void moreRelevantDocumentComesFirst() throws Exception {
        // Older but about nothing except overflows, so it scores higher than the newer, longer text.
        saveCve("CVE-2026-0001", "Overflow overflow overflow", Severity.HIGH, "2026-01-01T10:00:00Z");
        saveCve("CVE-2026-0002", "A flaw in the configuration parser of the network management service "
                + "allows a local user to cause an overflow and read memory of other processes",
                Severity.HIGH, "2026-02-01T10:00:00Z");
        indexAndRefresh("CVE-2026-0001", "CVE-2026-0002");

        mockMvc.perform(get("/api/cves/search").param("q", "overflow"))
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2026-0001", "CVE-2026-0002")));
    }

    @Test
    void pagesThroughResults() throws Exception {
        // Same text, so same score: newest first decides the order.
        saveCve("CVE-2026-0001", "Overflow", Severity.HIGH, "2026-01-01T10:00:00Z");
        saveCve("CVE-2026-0002", "Overflow", Severity.HIGH, "2026-01-02T10:00:00Z");
        saveCve("CVE-2026-0003", "Overflow", Severity.HIGH, "2026-01-03T10:00:00Z");
        indexAndRefresh("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003");

        mockMvc.perform(get("/api/cves/search").param("q", "overflow").param("size", "1").param("page", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2026-0002")))
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.size").value(1))
                .andExpect(jsonPath("$.totalItems").value(3))
                .andExpect(jsonPath("$.totalPages").value(3));
    }

    @Test
    void missingQueryIsRejectedAndSearchIsNotTreatedAsACveId() throws Exception {
        mockMvc.perform(get("/api/cves/search"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/problem+json"))
                .andExpect(jsonPath("$.detail", containsString("'q'")));
    }

    @Test
    void blankQueryIsRejected() throws Exception {
        mockMvc.perform(get("/api/cves/search").param("q", "   "))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/problem+json"))
                .andExpect(jsonPath("$.errors[0]", containsString("q:")));
    }

    @Test
    void pageBeyondTheResultWindowIsRejected() throws Exception {
        mockMvc.perform(get("/api/cves/search").param("q", "overflow").param("page", "100").param("size", "100"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/problem+json"))
                .andExpect(jsonPath("$.detail", containsString("result window")));
    }

    @Test
    void publishedFromAfterPublishedToIsRejected() throws Exception {
        mockMvc.perform(get("/api/cves/search").param("q", "overflow")
                        .param("publishedFrom", "2026-03-10").param("publishedTo", "2026-03-01"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("publishedFrom must not be after publishedTo"));
    }
}
