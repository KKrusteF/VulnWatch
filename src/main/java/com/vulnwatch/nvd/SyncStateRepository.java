package com.vulnwatch.nvd;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Database access for {@link SyncState}; the key is the feed name.
 */
public interface SyncStateRepository extends JpaRepository<SyncState, String> {
}
