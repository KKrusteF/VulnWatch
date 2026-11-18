package com.vulnwatch.cve;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * Database access for CVEs. Spring Data generates the implementation at startup:
 * {@link JpaRepository} gives CRUD and paging, {@link JpaSpecificationExecutor} gives dynamic filters.
 */
public interface CveRepository extends JpaRepository<Cve, String>, JpaSpecificationExecutor<Cve> {

    /** JPQL query: it works on entity and field names ({@code Cve}, {@code severity}), not table names. */
    @Query("select c.severity as severity, count(c) as total from Cve c group by c.severity")
    List<SeverityCount> countBySeverity();

    /** Native SQL query, because it reads the cve_vendor table directly. */
    @Query(nativeQuery = true, value = """
            select vendor as vendor, count(*) as total
            from cve_vendor
            group by vendor
            order by total desc, vendor asc
            limit :limit
            """)
    List<VendorCount> findTopVendors(@Param("limit") int limit);
}
