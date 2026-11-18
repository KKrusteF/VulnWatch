package com.vulnwatch.cve;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Set;

/**
 * A CVE as delivered by a feed, ready to be stored. It does not depend on where the data came from,
 * so the storage code does not need to know anything about the NVD JSON format.
 */
public record CveData(
        String id,
        String description,
        Severity severity,
        BigDecimal cvssScore,
        String cvssVersion,
        String vulnStatus,
        Instant publishedAt,
        Instant lastModifiedAt,
        Set<String> vendors) {
}
