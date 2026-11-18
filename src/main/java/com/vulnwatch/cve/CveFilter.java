package com.vulnwatch.cve;

import java.time.LocalDate;

/**
 * Optional filters for listing CVEs. A {@code null} field means "do not filter on this".
 */
public record CveFilter(Severity severity, String vendor, LocalDate publishedFrom, LocalDate publishedTo) {
}
