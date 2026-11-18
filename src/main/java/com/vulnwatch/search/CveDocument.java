package com.vulnwatch.search;

import com.vulnwatch.cve.CveResponse;
import com.vulnwatch.cve.Severity;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

/**
 * One CVE as stored in Elasticsearch. It is a separate type from {@link CveResponse} so the index
 * schema and the API schema can change independently: the index mapping is strict and rejects any
 * field it does not declare.
 */
public record CveDocument(
        String id,
        String description,
        String severity,
        BigDecimal cvssScore,
        String cvssVersion,
        String vulnStatus,
        List<String> vendors,
        Instant publishedAt,
        Instant lastModifiedAt) {

    public static CveDocument from(CveResponse cve) {
        return new CveDocument(cve.id(), cve.description(), cve.severity().name(), cve.cvssScore(),
                cve.cvssVersion(), cve.vulnStatus(), cve.vendors(), cve.publishedAt(), cve.lastModifiedAt());
    }

    public CveResponse toResponse() {
        return new CveResponse(id, description, Severity.valueOf(severity), cvssScore, cvssVersion, vulnStatus,
                publishedAt, lastModifiedAt, vendors == null ? List.of() : vendors);
    }
}
