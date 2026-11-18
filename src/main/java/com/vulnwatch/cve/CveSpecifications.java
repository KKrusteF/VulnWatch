package com.vulnwatch.cve;

import org.springframework.data.jpa.domain.Specification;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Building blocks for the CVE list query. Each method returns one WHERE condition;
 * {@link #matching(CveFilter)} combines only the ones the caller asked for.
 */
public final class CveSpecifications {

    private CveSpecifications() {
    }

    public static Specification<Cve> hasSeverity(Severity severity) {
        return (root, query, cb) -> cb.equal(root.get("severity"), severity);
    }

    /** Vendors are stored lower-case, so the input is normalised the same way. */
    public static Specification<Cve> hasVendor(String vendor) {
        String normalized = vendor.trim().toLowerCase(Locale.ROOT);
        return (root, query, cb) -> cb.isMember(normalized, root.<Collection<String>>get("vendors"));
    }

    /** Published at or after the start of {@code date} (UTC). */
    public static Specification<Cve> publishedOnOrAfter(LocalDate date) {
        Instant start = date.atStartOfDay(ZoneOffset.UTC).toInstant();
        return (root, query, cb) -> cb.greaterThanOrEqualTo(root.get("publishedAt"), start);
    }

    /** Published on or before {@code date}, i.e. before the start of the next day (UTC). */
    public static Specification<Cve> publishedOnOrBefore(LocalDate date) {
        Instant endExclusive = date.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();
        return (root, query, cb) -> cb.lessThan(root.get("publishedAt"), endExclusive);
    }

    /** Combines the filters that are set with AND. No filters means "match everything". */
    public static Specification<Cve> matching(CveFilter filter) {
        List<Specification<Cve>> parts = new ArrayList<>();
        if (filter.severity() != null) {
            parts.add(hasSeverity(filter.severity()));
        }
        if (filter.vendor() != null && !filter.vendor().isBlank()) {
            parts.add(hasVendor(filter.vendor()));
        }
        if (filter.publishedFrom() != null) {
            parts.add(publishedOnOrAfter(filter.publishedFrom()));
        }
        if (filter.publishedTo() != null) {
            parts.add(publishedOnOrBefore(filter.publishedTo()));
        }
        return Specification.allOf(parts);
    }
}
