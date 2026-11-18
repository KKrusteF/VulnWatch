package com.vulnwatch.cve;

/**
 * One row of the "count per severity" query. Spring Data creates the implementation
 * and maps the query's column aliases to the getter names.
 */
public interface SeverityCount {

    Severity getSeverity();

    long getTotal();
}
