package com.vulnwatch.cve;

import com.vulnwatch.events.CveEvent;
import com.vulnwatch.events.OutboxEvent;
import com.vulnwatch.events.OutboxRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Write-side logic for CVEs: inserts new ones and updates stored ones when the feed has a newer
 * version, keyed by CVE ID, so feeding the same data twice never creates duplicates. Every created or
 * updated CVE also gets a row in the outbox table, written in the same transaction (transactional outbox).
 */
@Service
public class CveUpsertService {

    private final CveRepository repository;
    private final OutboxRepository outboxRepository;
    private final Clock clock;

    public CveUpsertService(CveRepository repository, OutboxRepository outboxRepository, Clock clock) {
        this.repository = repository;
        this.outboxRepository = outboxRepository;
        this.clock = clock;
    }

    /** Stores a batch of CVEs in one transaction: either the whole batch is saved or none of it. */
    @Transactional
    public UpsertResult upsertAll(Collection<CveData> incoming) {
        // The same CVE can appear twice in one batch; keep the most recently modified version.
        Map<String, CveData> latestById = incoming.stream().collect(Collectors.toMap(
                CveData::id, Function.identity(),
                (a, b) -> b.lastModifiedAt().isAfter(a.lastModifiedAt()) ? b : a,
                LinkedHashMap::new));

        // One SELECT for the whole batch instead of one per CVE.
        Map<String, Cve> existingById = repository.findAllById(latestById.keySet()).stream()
                .collect(Collectors.toMap(Cve::getId, Function.identity()));

        int created = 0;
        int updated = 0;
        int unchanged = 0;
        Instant now = clock.instant();
        List<OutboxEvent> events = new ArrayList<>();
        for (CveData data : latestById.values()) {
            Cve existing = existingById.get(data.id());
            if (existing == null) {
                repository.save(Cve.from(data));
                events.add(new OutboxEvent(data.id(), CveEvent.CREATED, data.lastModifiedAt(), now));
                created++;
            } else if (data.lastModifiedAt().isAfter(existing.getLastModifiedAt())) {
                // No save() needed: the entity was loaded in this transaction, so Hibernate tracks it
                // ("dirty checking") and writes the changes with an UPDATE when the transaction commits.
                existing.applyUpdate(data);
                events.add(new OutboxEvent(data.id(), CveEvent.UPDATED, data.lastModifiedAt(), now));
                updated++;
            } else {
                unchanged++;
            }
        }
        // Same transaction as the CVE changes: either both are stored or neither is, so no change can be
        // saved without its event and no event can exist for a change that was rolled back.
        outboxRepository.saveAll(events);
        return new UpsertResult(created, updated, unchanged);
    }
}
