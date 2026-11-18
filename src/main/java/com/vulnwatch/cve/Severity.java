package com.vulnwatch.cve;

/**
 * CVSS severity rating of a CVE. UNKNOWN is used when NVD has not scored the CVE yet.
 */
public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    NONE,
    UNKNOWN
}
