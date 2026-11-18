package com.vulnwatch.nvd;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * One page of the NVD CVE API 2.0 response. The records mirror only the JSON fields VulnWatch uses;
 * Jackson ignores everything else. Missing lists become empty lists, so callers never see null.
 */
public record NvdPage(int resultsPerPage, int startIndex, int totalResults, List<Vulnerability> vulnerabilities) {

    public NvdPage {
        vulnerabilities = orEmpty(vulnerabilities);
    }

    public record Vulnerability(CveItem cve) {
    }

    /** NVD sends timestamps in UTC but without a zone, so they are read as LocalDateTime. */
    public record CveItem(
            String id,
            LocalDateTime published,
            LocalDateTime lastModified,
            String vulnStatus,
            List<Description> descriptions,
            Metrics metrics,
            List<Configuration> configurations) {

        public CveItem {
            descriptions = orEmpty(descriptions);
            metrics = metrics == null ? new Metrics(null, null, null, null) : metrics;
            configurations = orEmpty(configurations);
        }
    }

    public record Description(String lang, String value) {
    }

    /** CVSS scores by CVSS version. A CVE can have scores from NVD ("Primary") and others ("Secondary"). */
    public record Metrics(
            List<Metric> cvssMetricV40,
            List<Metric> cvssMetricV31,
            List<Metric> cvssMetricV30,
            List<Metric> cvssMetricV2) {

        public Metrics {
            cvssMetricV40 = orEmpty(cvssMetricV40);
            cvssMetricV31 = orEmpty(cvssMetricV31);
            cvssMetricV30 = orEmpty(cvssMetricV30);
            cvssMetricV2 = orEmpty(cvssMetricV2);
        }
    }

    /** CVSS v2 puts baseSeverity here instead of inside cvssData. */
    public record Metric(String type, CvssData cvssData, String baseSeverity) {
    }

    public record CvssData(String version, BigDecimal baseScore, String baseSeverity) {
    }

    public record Configuration(List<Node> nodes) {

        public Configuration {
            nodes = orEmpty(nodes);
        }
    }

    public record Node(List<CpeMatch> cpeMatch) {

        public Node {
            cpeMatch = orEmpty(cpeMatch);
        }
    }

    /** A CPE name such as {@code cpe:2.3:a:apache:log4j:...}; the vendor is the 4th field. */
    public record CpeMatch(boolean vulnerable, String criteria) {
    }

    private static <T> List<T> orEmpty(List<T> list) {
        return list == null ? List.of() : list;
    }
}
