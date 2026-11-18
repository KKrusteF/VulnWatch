package com.vulnwatch.nvd;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.vulnwatch.cve.CveData;
import com.vulnwatch.cve.Severity;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.math.BigDecimal;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link NvdCveMapper}: plain JUnit, no Spring. The JSON is parsed with an
 * ObjectMapper configured like Spring Boot's, so the records are tested as the app uses them.
 */
class NvdCveMapperTest {

    private final ObjectMapper objectMapper = JsonMapper.builder()
            .addModule(new JavaTimeModule())
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    @Test
    void prefersPrimaryMetricOverSecondary() throws Exception {
        CveData data = map("""
                "metrics": {"cvssMetricV31": [
                  {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}},
                  {"type": "Primary",   "cvssData": {"version": "3.1", "baseScore": 5.3, "baseSeverity": "MEDIUM"}}
                ]}""");

        assertThat(data.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(data.cvssScore()).isEqualByComparingTo("5.3");
        assertThat(data.cvssVersion()).isEqualTo("3.1");
    }

    @Test
    void prefersNewestCvssVersion() throws Exception {
        CveData data = map("""
                "metrics": {
                  "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH"}}],
                  "cvssMetricV40": [{"type": "Secondary", "cvssData": {"version": "4.0", "baseScore": 9.3, "baseSeverity": "CRITICAL"}}]
                }""");

        assertThat(data.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(data.cvssScore()).isEqualByComparingTo("9.3");
        assertThat(data.cvssVersion()).isEqualTo("4.0");
    }

    @Test
    void takesCvssV2SeverityFromTheMetric() throws Exception {
        CveData data = map("""
                "metrics": {"cvssMetricV2": [
                  {"type": "Primary", "baseSeverity": "MEDIUM", "cvssData": {"version": "2.0", "baseScore": 4.3}}
                ]}""");

        assertThat(data.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(data.cvssScore()).isEqualByComparingTo("4.3");
        assertThat(data.cvssVersion()).isEqualTo("2.0");
    }

    @Test
    void cveWithoutMetricsIsUnknown() throws Exception {
        CveData data = map("\"metrics\": {}");

        assertThat(data.severity()).isEqualTo(Severity.UNKNOWN);
        assertThat(data.cvssScore()).isNull();
        assertThat(data.cvssVersion()).isNull();
    }

    @Test
    void cveWithoutMetricsFieldIsUnknown() throws Exception {
        CveData data = map("\"vulnStatus\": \"Received\"");

        assertThat(data.severity()).isEqualTo(Severity.UNKNOWN);
        assertThat(data.cvssScore()).isNull();
        assertThat(data.vendors()).isEmpty();
    }

    @Test
    void choosesEnglishDescription() throws Exception {
        CveData data = map("""
                "descriptions": [
                  {"lang": "es", "value": "Descripción en español"},
                  {"lang": "en", "value": "English description"}
                ]""");

        assertThat(data.description()).isEqualTo("English description");
    }

    @Test
    void fallsBackToFirstDescriptionThenEmpty() throws Exception {
        assertThat(map("\"descriptions\": [{\"lang\": \"es\", \"value\": \"Solo español\"}]").description())
                .isEqualTo("Solo español");
        assertThat(map("\"descriptions\": []").description()).isEmpty();
    }

    @Test
    void vendorsComeOnlyFromVulnerableCpesLowerCasedAndDistinct() throws Exception {
        CveData data = map("""
                "configurations": [
                  {"nodes": [{"cpeMatch": [
                    {"vulnerable": true,  "criteria": "cpe:2.3:a:Apache:log4j:2.0:*:*:*:*:*:*:*"},
                    {"vulnerable": true,  "criteria": "cpe:2.3:a:apache:log4j:2.1:*:*:*:*:*:*:*"},
                    {"vulnerable": false, "criteria": "cpe:2.3:o:debian:debian_linux:10:*:*:*:*:*:*:*"},
                    {"vulnerable": true,  "criteria": "cpe:2.3:a:*:something:*:*:*:*:*:*:*:*"},
                    {"vulnerable": true,  "criteria": "cpe:2.3:a:-:other:*:*:*:*:*:*:*:*"}
                  ]}]},
                  {"nodes": [{"cpeMatch": [
                    {"vulnerable": true,  "criteria": "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*"}
                  ]}]}
                ]""");

        assertThat(data.vendors()).containsExactlyInAnyOrder("apache", "cisco");
    }

    @Test
    void timestampsAreReadAsUtc() throws Exception {
        CveData data = map("\"vulnStatus\": \"Analyzed\"");

        assertThat(data.publishedAt()).isEqualTo(Instant.parse("2024-01-02T03:04:05.678Z"));
        assertThat(data.lastModifiedAt()).isEqualTo(Instant.parse("2024-02-03T04:05:06.789Z"));
    }

    @Test
    void mapsRealNvdResponse() throws Exception {
        NvdPage page;
        try (InputStream json = getClass().getResourceAsStream("/nvd/real-page.json")) {
            page = objectMapper.readValue(json, NvdPage.class);
        }

        assertThat(page.totalResults()).isEqualTo(33);
        assertThat(page.vulnerabilities()).hasSize(3);

        CveData first = NvdCveMapper.toCveData(page.vulnerabilities().getFirst().cve());
        assertThat(first.id()).isEqualTo("CVE-2021-43803");
        assertThat(first.description()).startsWith("Next.js is a React framework.");
        // Only a Secondary v3.1 score exists, so it wins over the older v2 Primary score.
        assertThat(first.severity()).isEqualTo(Severity.HIGH);
        assertThat(first.cvssScore()).isEqualByComparingTo(new BigDecimal("7.5"));
        assertThat(first.cvssVersion()).isEqualTo("3.1");
        assertThat(first.vulnStatus()).isEqualTo("Modified");
        assertThat(first.publishedAt()).isEqualTo(Instant.parse("2021-12-10T00:15:11.827Z"));
        assertThat(first.lastModifiedAt()).isEqualTo(Instant.parse("2026-06-17T04:11:28.210Z"));
        assertThat(first.vendors()).containsExactly("vercel");
    }

    /** Parses one NVD CVE built from fixed defaults plus the given extra JSON fields. */
    private CveData map(String extraFields) throws Exception {
        String json = """
                {
                  "id": "CVE-2024-0001",
                  "published": "2024-01-02T03:04:05.678",
                  "lastModified": "2024-02-03T04:05:06.789",
                  "vulnStatus": "Analyzed",
                  %s
                }""".formatted(extraFields);
        // A later field with the same name overrides the default above (e.g. vulnStatus).
        return NvdCveMapper.toCveData(objectMapper.readValue(json, NvdPage.CveItem.class));
    }
}
