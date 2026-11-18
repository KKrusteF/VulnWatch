package com.vulnwatch.cve;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * A CVE as stored in the {@code cve} table. This JPA entity is the database view of a CVE;
 * the API never returns it directly (see {@link CveResponse}).
 */
@Entity
@Table(name = "cve")
public class Cve {

    @Id
    @Column(name = "cve_id")
    private String id;

    private String description;

    // Stored as the enum name ("CRITICAL"), not its position, so reordering the enum is safe.
    @Enumerated(EnumType.STRING)
    private Severity severity;

    @Column(precision = 3, scale = 1)
    private BigDecimal cvssScore;

    private String cvssVersion;

    private String vulnStatus;

    private Instant publishedAt;

    private Instant lastModifiedAt;

    // A set of plain strings kept in its own table (cve_vendor), loaded lazily on first access.
    @ElementCollection
    @CollectionTable(name = "cve_vendor", joinColumns = @JoinColumn(name = "cve_id"))
    @Column(name = "vendor")
    private Set<String> vendors = new HashSet<>();

    /** Required by JPA, which creates the object first and then fills in the fields. */
    protected Cve() {
    }

    public Cve(String id, String description, Severity severity, BigDecimal cvssScore, String cvssVersion,
               String vulnStatus, Instant publishedAt, Instant lastModifiedAt, Set<String> vendors) {
        this.id = id;
        this.description = description;
        this.severity = severity;
        this.cvssScore = cvssScore;
        this.cvssVersion = cvssVersion;
        this.vulnStatus = vulnStatus;
        this.publishedAt = publishedAt;
        this.lastModifiedAt = lastModifiedAt;
        this.vendors = new HashSet<>(vendors);
    }

    public String getId() {
        return id;
    }

    public String getDescription() {
        return description;
    }

    public Severity getSeverity() {
        return severity;
    }

    public BigDecimal getCvssScore() {
        return cvssScore;
    }

    public String getCvssVersion() {
        return cvssVersion;
    }

    public String getVulnStatus() {
        return vulnStatus;
    }

    public Instant getPublishedAt() {
        return publishedAt;
    }

    public Instant getLastModifiedAt() {
        return lastModifiedAt;
    }

    public Set<String> getVendors() {
        return vendors;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Cve other)) {
            return false;
        }
        return id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id);
    }
}
