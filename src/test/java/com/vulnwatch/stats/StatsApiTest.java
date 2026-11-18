package com.vulnwatch.stats;

import com.vulnwatch.AbstractIntegrationTest;
import com.vulnwatch.cve.Severity;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end tests of {@code GET /api/stats}.
 */
class StatsApiTest extends AbstractIntegrationTest {

    @Test
    void emptyDatabaseReportsZeroForEverySeverity() throws Exception {
        mockMvc.perform(get("/api/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCves").value(0))
                .andExpect(jsonPath("$.bySeverity.CRITICAL").value(0))
                .andExpect(jsonPath("$.bySeverity.HIGH").value(0))
                .andExpect(jsonPath("$.bySeverity.MEDIUM").value(0))
                .andExpect(jsonPath("$.bySeverity.LOW").value(0))
                .andExpect(jsonPath("$.bySeverity.NONE").value(0))
                .andExpect(jsonPath("$.bySeverity.UNKNOWN").value(0))
                .andExpect(jsonPath("$.topVendors", hasSize(0)));
    }

    @Test
    void countsSeveritiesAndRanksVendors() throws Exception {
        saveCve("CVE-2024-0001", Severity.CRITICAL, "2024-01-01T00:00:00Z", "apache", "oracle");
        saveCve("CVE-2024-0002", Severity.CRITICAL, "2024-01-02T00:00:00Z", "apache", "microsoft");
        saveCve("CVE-2024-0003", Severity.HIGH, "2024-01-03T00:00:00Z", "apache");
        saveCve("CVE-2024-0004", Severity.UNKNOWN, "2024-01-04T00:00:00Z", "microsoft");
        saveCve("CVE-2024-0005", Severity.LOW, "2024-01-05T00:00:00Z", "oracle");

        mockMvc.perform(get("/api/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCves").value(5))
                .andExpect(jsonPath("$.bySeverity.CRITICAL").value(2))
                .andExpect(jsonPath("$.bySeverity.HIGH").value(1))
                .andExpect(jsonPath("$.bySeverity.MEDIUM").value(0))
                .andExpect(jsonPath("$.bySeverity.LOW").value(1))
                .andExpect(jsonPath("$.bySeverity.NONE").value(0))
                .andExpect(jsonPath("$.bySeverity.UNKNOWN").value(1))
                .andExpect(jsonPath("$.topVendors", hasSize(3)))
                // apache has 3; microsoft and oracle tie at 2 and are ordered by name.
                .andExpect(jsonPath("$.topVendors[0].vendor").value("apache"))
                .andExpect(jsonPath("$.topVendors[0].count").value(3))
                .andExpect(jsonPath("$.topVendors[1].vendor").value("microsoft"))
                .andExpect(jsonPath("$.topVendors[1].count").value(2))
                .andExpect(jsonPath("$.topVendors[2].vendor").value("oracle"))
                .andExpect(jsonPath("$.topVendors[2].count").value(2));
    }

    @Test
    void topVendorsParameterLimitsTheList() throws Exception {
        saveCve("CVE-2024-0001", Severity.HIGH, "2024-01-01T00:00:00Z", "apache", "oracle");
        saveCve("CVE-2024-0002", Severity.HIGH, "2024-01-02T00:00:00Z", "apache");

        mockMvc.perform(get("/api/stats").param("topVendors", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.topVendors", hasSize(1)))
                .andExpect(jsonPath("$.topVendors[0].vendor").value("apache"))
                .andExpect(jsonPath("$.topVendors[0].count").value(2));
    }
}
