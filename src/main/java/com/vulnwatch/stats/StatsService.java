package com.vulnwatch.stats;

import com.vulnwatch.cve.CveRepository;
import com.vulnwatch.cve.Severity;
import com.vulnwatch.cve.SeverityCount;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Computes aggregate statistics with GROUP BY queries, so Postgres does the counting.
 */
@Service
@Transactional(readOnly = true)
public class StatsService {

    private final CveRepository repository;

    public StatsService(CveRepository repository) {
        this.repository = repository;
    }

    public StatsResponse getStats(int topVendorLimit) {
        // Start every severity at 0 so the JSON always lists all of them, in enum order.
        Map<Severity, Long> bySeverity = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            bySeverity.put(severity, 0L);
        }
        for (SeverityCount row : repository.countBySeverity()) {
            bySeverity.put(row.getSeverity(), row.getTotal());
        }
        long total = bySeverity.values().stream().mapToLong(Long::longValue).sum();

        List<StatsResponse.VendorStat> topVendors = repository.findTopVendors(topVendorLimit).stream()
                .map(row -> new StatsResponse.VendorStat(row.getVendor(), row.getTotal()))
                .toList();

        return new StatsResponse(total, bySeverity, topVendors);
    }
}
