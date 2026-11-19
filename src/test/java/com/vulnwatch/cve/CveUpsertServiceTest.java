package com.vulnwatch.cve;

import com.vulnwatch.AbstractIntegrationTest;
import com.vulnwatch.events.CveEvent;
import com.vulnwatch.events.OutboxEvent;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

/**
 * Tests the transactional outbox side of the upsert: which changes produce an event row, and that
 * CVE and event row are stored or rolled back together.
 */
class CveUpsertServiceTest extends AbstractIntegrationTest {

    @Autowired
    CveUpsertService upsertService;

    @Test
    void writesOneOutboxRowPerCreatedAndUpdatedCveAndNoneForUnchanged() {
        upsertService.upsertAll(List.of(
                data("CVE-2026-0001", "2026-11-01T10:00:00Z"),
                data("CVE-2026-0002", "2026-11-01T10:00:00Z")));

        assertThat(outboxRows()).extracting(OutboxEvent::getCveId, OutboxEvent::getEventType)
                .containsExactly(tuple("CVE-2026-0001", CveEvent.CREATED), tuple("CVE-2026-0002", CveEvent.CREATED));

        UpsertResult second = upsertService.upsertAll(List.of(
                data("CVE-2026-0001", "2026-11-02T10:00:00Z"),
                data("CVE-2026-0002", "2026-11-01T10:00:00Z")));

        assertThat(second.updated()).isEqualTo(1);
        assertThat(second.unchanged()).isEqualTo(1);
        List<OutboxEvent> rows = outboxRows();
        assertThat(rows).hasSize(3);
        assertThat(rows.get(2).getCveId()).isEqualTo("CVE-2026-0001");
        assertThat(rows.get(2).getEventType()).isEqualTo(CveEvent.UPDATED);
        assertThat(rows.get(2).getLastModifiedAt()).isEqualTo(Instant.parse("2026-11-02T10:00:00Z"));
    }

    @Test
    void failedTransactionStoresNeitherTheCvesNorTheirOutboxRows() {
        // The second ID breaks the CHECK constraint on cve_id, so the whole batch fails at commit.
        assertThatThrownBy(() -> upsertService.upsertAll(List.of(
                data("CVE-2026-0001", "2026-11-01T10:00:00Z"),
                data("NOT-A-CVE", "2026-11-01T10:00:00Z"))))
                .isInstanceOf(RuntimeException.class);

        assertThat(cveRepository.count()).isZero();
        assertThat(outboxRepository.count()).isZero();
    }

    private List<OutboxEvent> outboxRows() {
        return outboxRepository.findAll().stream()
                .sorted(Comparator.comparing(OutboxEvent::getId))
                .toList();
    }

    private static CveData data(String id, String lastModified) {
        Instant modified = Instant.parse(lastModified);
        return new CveData(id, "Description of " + id, Severity.HIGH, new BigDecimal("7.5"), "3.1",
                "Analyzed", Instant.parse("2026-11-01T00:00:00Z"), modified, Set.of("apache"));
    }
}
