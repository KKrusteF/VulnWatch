package com.vulnwatch.cve;

import com.vulnwatch.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Set;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end tests of {@code /api/cves}: HTTP request in, JSON out, real Postgres underneath.
 */
class CveApiTest extends AbstractIntegrationTest {

    @Test
    void getByIdReturnsAllFieldsWithSortedVendors() throws Exception {
        cveRepository.save(new Cve("CVE-2021-44228", "Apache Log4j2 JNDI features ...", Severity.CRITICAL,
                new BigDecimal("10.0"), "3.1", "Analyzed",
                Instant.parse("2021-12-10T10:15:09Z"), Instant.parse("2024-04-03T17:15:09Z"),
                Set.of("siemens", "apache", "cisco")));

        mockMvc.perform(get("/api/cves/CVE-2021-44228"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("CVE-2021-44228"))
                .andExpect(jsonPath("$.description").value("Apache Log4j2 JNDI features ..."))
                .andExpect(jsonPath("$.severity").value("CRITICAL"))
                .andExpect(jsonPath("$.cvssScore").value(10.0))
                .andExpect(jsonPath("$.cvssVersion").value("3.1"))
                .andExpect(jsonPath("$.vulnStatus").value("Analyzed"))
                .andExpect(jsonPath("$.publishedAt").value("2021-12-10T10:15:09Z"))
                .andExpect(jsonPath("$.lastModifiedAt").value("2024-04-03T17:15:09Z"))
                .andExpect(jsonPath("$.vendors", contains("apache", "cisco", "siemens")));
    }

    @Test
    void getByIdAcceptsLowerCaseId() throws Exception {
        saveCve("CVE-2021-44228", Severity.CRITICAL, "2021-12-10T10:15:09Z", "apache");

        mockMvc.perform(get("/api/cves/cve-2021-44228"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("CVE-2021-44228"));
    }

    @Test
    void unknownIdReturns404ProblemDetail() throws Exception {
        mockMvc.perform(get("/api/cves/CVE-1999-0001"))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.title").value("CVE not found"))
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.detail", containsString("CVE-1999-0001")));
    }

    @Test
    void malformedIdReturns400WithErrors() throws Exception {
        mockMvc.perform(get("/api/cves/nope"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.errors", hasSize(1)))
                .andExpect(jsonPath("$.errors[0]").value("id: must look like CVE-2021-44228"));
    }

    @Test
    void listReturnsNewestFirstWithPageMetadata() throws Exception {
        saveCve("CVE-2024-0001", Severity.HIGH, "2024-01-01T00:00:00Z");
        saveCve("CVE-2024-0003", Severity.LOW, "2024-03-01T00:00:00Z");
        saveCve("CVE-2024-0002", Severity.MEDIUM, "2024-02-01T00:00:00Z");

        mockMvc.perform(get("/api/cves"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2024-0003", "CVE-2024-0002", "CVE-2024-0001")))
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(20))
                .andExpect(jsonPath("$.totalItems").value(3))
                .andExpect(jsonPath("$.totalPages").value(1));
    }

    @Test
    void filtersBySeverityInAnyCase() throws Exception {
        saveCve("CVE-2024-0001", Severity.CRITICAL, "2024-01-01T00:00:00Z");
        saveCve("CVE-2024-0002", Severity.HIGH, "2024-01-02T00:00:00Z");
        saveCve("CVE-2024-0003", Severity.CRITICAL, "2024-01-03T00:00:00Z");

        mockMvc.perform(get("/api/cves").param("severity", "CRITICAL"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2024-0003", "CVE-2024-0001")));

        mockMvc.perform(get("/api/cves").param("severity", "critical"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2024-0003", "CVE-2024-0001")));
    }

    @Test
    void filtersByVendorCaseInsensitively() throws Exception {
        saveCve("CVE-2024-0001", Severity.HIGH, "2024-01-01T00:00:00Z", "apache", "oracle");
        saveCve("CVE-2024-0002", Severity.HIGH, "2024-01-02T00:00:00Z", "microsoft");
        saveCve("CVE-2024-0003", Severity.HIGH, "2024-01-03T00:00:00Z", "apache");

        mockMvc.perform(get("/api/cves").param("vendor", " Apache "))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(2))
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2024-0003", "CVE-2024-0001")))
                .andExpect(jsonPath("$.items[1].vendors", contains("apache", "oracle")));
    }

    @Test
    void dateRangeIsInclusiveOnBothEnds() throws Exception {
        saveCve("CVE-2024-0001", Severity.HIGH, "2024-01-09T23:59:59Z");
        saveCve("CVE-2024-0002", Severity.HIGH, "2024-01-10T00:00:00Z");
        saveCve("CVE-2024-0003", Severity.HIGH, "2024-01-12T23:59:59Z");
        saveCve("CVE-2024-0004", Severity.HIGH, "2024-01-13T00:00:00Z");

        mockMvc.perform(get("/api/cves").param("publishedFrom", "2024-01-10").param("publishedTo", "2024-01-12"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2024-0003", "CVE-2024-0002")));

        mockMvc.perform(get("/api/cves").param("publishedFrom", "2024-01-12"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2024-0004", "CVE-2024-0003")));

        mockMvc.perform(get("/api/cves").param("publishedTo", "2024-01-09"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2024-0001")));
    }

    @Test
    void combinesFilters() throws Exception {
        saveCve("CVE-2024-0001", Severity.CRITICAL, "2024-01-01T00:00:00Z", "apache");
        saveCve("CVE-2024-0002", Severity.CRITICAL, "2024-02-01T00:00:00Z", "apache");
        saveCve("CVE-2024-0003", Severity.HIGH, "2024-02-02T00:00:00Z", "apache");
        saveCve("CVE-2024-0004", Severity.CRITICAL, "2024-02-03T00:00:00Z", "microsoft");

        mockMvc.perform(get("/api/cves")
                        .param("severity", "critical")
                        .param("vendor", "apache")
                        .param("publishedFrom", "2024-02-01"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1))
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2024-0002")));
    }

    @Test
    void paginates() throws Exception {
        saveCve("CVE-2024-0001", Severity.HIGH, "2024-01-01T00:00:00Z");
        saveCve("CVE-2024-0002", Severity.HIGH, "2024-01-02T00:00:00Z");
        saveCve("CVE-2024-0003", Severity.HIGH, "2024-01-03T00:00:00Z");
        saveCve("CVE-2024-0004", Severity.HIGH, "2024-01-04T00:00:00Z");
        saveCve("CVE-2024-0005", Severity.HIGH, "2024-01-05T00:00:00Z");

        mockMvc.perform(get("/api/cves").param("size", "2").param("page", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].id", contains("CVE-2024-0003", "CVE-2024-0002")))
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.size").value(2))
                .andExpect(jsonPath("$.totalItems").value(5))
                .andExpect(jsonPath("$.totalPages").value(3));
    }

    @Test
    void rejectsFromAfterTo() throws Exception {
        mockMvc.perform(get("/api/cves").param("publishedFrom", "2024-02-01").param("publishedTo", "2024-01-01"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.detail").value("publishedFrom must not be after publishedTo"));
    }

    @Test
    void rejectsTooLargePageSize() throws Exception {
        mockMvc.perform(get("/api/cves").param("size", "101"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.errors", hasItem(containsString("size:"))));
    }

    @Test
    void rejectsUnknownSeverity() throws Exception {
        mockMvc.perform(get("/api/cves").param("severity", "bogus"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
    }
}
