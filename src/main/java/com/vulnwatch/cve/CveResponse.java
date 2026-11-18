package com.vulnwatch.cve;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

/**
 * The JSON shape of a CVE returned by the API. Keeping it separate from the {@link Cve}
 * entity means database changes do not silently change the API.
 */
public record CveResponse(
        String id,
        String description,
        Severity severity,
        BigDecimal cvssScore,
        String cvssVersion,
        String vulnStatus,
        Instant publishedAt,
        Instant lastModifiedAt,
        List<String> vendors) {

    public static CveResponse from(Cve cve) {
        return new CveResponse(
                cve.getId(),
                cve.getDescription(),
                cve.getSeverity(),
                cve.getCvssScore(),
                cve.getCvssVersion(),
                cve.getVulnStatus(),
                cve.getPublishedAt(),
                cve.getLastModifiedAt(),
                cve.getVendors().stream().sorted().toList());
    }
}
