package com.vulnwatch;

import com.vulnwatch.cve.Cve;
import com.vulnwatch.cve.CveRepository;
import com.vulnwatch.cve.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Set;

/**
 * Base class for tests that start the whole application against a real Postgres container.
 * Spring caches the application context, so all subclasses share one app and one container.
 * The scheduled NVD sync is switched off so tests never call the real NVD.
 */
@SpringBootTest(properties = "vulnwatch.nvd.enabled=false")
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
public abstract class AbstractIntegrationTest {

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected CveRepository cveRepository;

    @BeforeEach
    void cleanDatabase() {
        cveRepository.deleteAll();
    }

    /** Saves a CVE with sensible defaults for the fields a test does not care about. */
    protected Cve saveCve(String id, Severity severity, String publishedAt, String... vendors) {
        Instant published = Instant.parse(publishedAt);
        Cve cve = new Cve(id, "Description of " + id, severity, new BigDecimal("7.5"), "3.1",
                "Analyzed", published, published.plusSeconds(3600), Set.of(vendors));
        return cveRepository.save(cve);
    }
}
