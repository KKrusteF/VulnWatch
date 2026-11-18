package com.vulnwatch.nvd;

import com.vulnwatch.cve.CveData;
import com.vulnwatch.cve.Severity;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * Converts an NVD CVE into {@link CveData}. Plain Java with no Spring, so it is easy to unit test.
 */
public final class NvdCveMapper {

    private NvdCveMapper() {
    }

    public static CveData toCveData(NvdPage.CveItem cve) {
        NvdPage.Metric metric = pickMetric(cve.metrics());
        NvdPage.CvssData cvss = metric == null ? null : metric.cvssData();
        BigDecimal score = cvss == null ? null : cvss.baseScore();
        String version = cvss == null ? null : cvss.version();

        return new CveData(
                cve.id(),
                pickDescription(cve.descriptions()),
                severityOf(metric),
                score,
                version,
                cve.vulnStatus(),
                toInstant(cve.published()),
                toInstant(cve.lastModified()),
                vendorsOf(cve.configurations()));
    }

    /** The English description, else the first one, else an empty string. */
    static String pickDescription(List<NvdPage.Description> descriptions) {
        return descriptions.stream()
                .filter(d -> "en".equals(d.lang()))
                .findFirst()
                .or(() -> descriptions.stream().findFirst())
                .map(NvdPage.Description::value)
                .orElse("");
    }

    /** The newest CVSS version that has a score; within it NVD's own ("Primary") score if present. */
    static NvdPage.Metric pickMetric(NvdPage.Metrics metrics) {
        return Stream.of(metrics.cvssMetricV40(), metrics.cvssMetricV31(), metrics.cvssMetricV30(),
                        metrics.cvssMetricV2())
                .filter(list -> !list.isEmpty())
                .findFirst()
                .map(list -> list.stream()
                        .filter(m -> "Primary".equals(m.type()))
                        .findFirst()
                        .orElse(list.getFirst()))
                .orElse(null);
    }

    static Severity severityOf(NvdPage.Metric metric) {
        if (metric == null) {
            return Severity.UNKNOWN;
        }
        String value = metric.cvssData() != null && metric.cvssData().baseSeverity() != null
                ? metric.cvssData().baseSeverity()
                : metric.baseSeverity();
        if (value == null) {
            return Severity.UNKNOWN;
        }
        try {
            return Severity.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return Severity.UNKNOWN;
        }
    }

    /** Distinct lower-case vendor names from the CPE names marked as vulnerable. */
    static Set<String> vendorsOf(List<NvdPage.Configuration> configurations) {
        Set<String> vendors = new TreeSet<>();
        for (NvdPage.Configuration configuration : configurations) {
            for (NvdPage.Node node : configuration.nodes()) {
                for (NvdPage.CpeMatch match : node.cpeMatch()) {
                    if (!match.vulnerable() || match.criteria() == null) {
                        continue;
                    }
                    String[] parts = match.criteria().split(":");
                    if (parts.length <= 3) {
                        continue;
                    }
                    String vendor = parts[3].trim().toLowerCase(Locale.ROOT);
                    if (!vendor.isEmpty() && !vendor.equals("*") && !vendor.equals("-")) {
                        vendors.add(vendor);
                    }
                }
            }
        }
        return vendors;
    }

    private static Instant toInstant(LocalDateTime utc) {
        return utc == null ? null : utc.toInstant(ZoneOffset.UTC);
    }
}
