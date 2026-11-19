package com.vulnwatch.events;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * Database access for the outbox table.
 */
public interface OutboxRepository extends JpaRepository<OutboxEvent, Long> {

    /**
     * Locks the oldest unsent rows until the transaction ends. SKIP LOCKED makes a second app instance
     * skip rows another instance is already sending, so two publishers never pick the same rows.
     */
    @Query(nativeQuery = true, value = """
            select *
            from cve_outbox
            order by id
            limit :limit
            for update skip locked
            """)
    List<OutboxEvent> lockOldest(@Param("limit") int limit);
}
