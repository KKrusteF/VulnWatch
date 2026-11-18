package com.vulnwatch.stats;

import com.vulnwatch.cve.Severity;

import java.util.List;
import java.util.Map;

/**
 * JSON shape of {@code GET /api/stats}: total CVEs, a count for every severity and the top vendors.
 */
public record StatsResponse(long totalCves, Map<Severity, Long> bySeverity, List<VendorStat> topVendors) {

    /** A vendor and the number of CVEs that affect it. */
    public record VendorStat(String vendor, long count) {
    }
}
