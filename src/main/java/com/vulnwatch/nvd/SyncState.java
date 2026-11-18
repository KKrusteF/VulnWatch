package com.vulnwatch.nvd;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * Remembers how far a feed has been synced, so the next sync only asks for what changed since.
 */
@Entity
@Table(name = "sync_state")
public class SyncState {

    @Id
    private String source;

    private Instant lastSyncedUntil;

    private Instant updatedAt;

    protected SyncState() {
    }

    public SyncState(String source, Instant lastSyncedUntil, Instant updatedAt) {
        this.source = source;
        this.lastSyncedUntil = lastSyncedUntil;
        this.updatedAt = updatedAt;
    }

    public void advanceTo(Instant syncedUntil, Instant now) {
        this.lastSyncedUntil = syncedUntil;
        this.updatedAt = now;
    }

    public String getSource() {
        return source;
    }

    public Instant getLastSyncedUntil() {
        return lastSyncedUntil;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
