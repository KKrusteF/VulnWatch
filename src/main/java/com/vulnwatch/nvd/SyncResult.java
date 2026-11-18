package com.vulnwatch.nvd;

import java.time.Instant;

/**
 * Summary of one sync run: the time window asked for and what happened to the CVEs received.
 */
public record SyncResult(Instant from, Instant to, int fetched, int created, int updated, int unchanged) {
}
