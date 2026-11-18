package com.vulnwatch.nvd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Calls the NVD CVE API. Keeps requests at least {@code request-interval} apart to stay under the
 * rate limit, and retries rate-limit and server errors with the retry template's backoff.
 */
@Component
public class NvdClient {

    private static final Logger log = LoggerFactory.getLogger(NvdClient.class);

    private static final DateTimeFormatter NVD_DATE =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    private final RestClient restClient;
    private final RetryTemplate retryTemplate;
    private final int resultsPerPage;
    private final long requestIntervalNanos;

    private long lastRequestStartNanos;
    private boolean anyRequestSent;

    public NvdClient(RestClient nvdRestClient, RetryTemplate nvdRetryTemplate, NvdProperties properties) {
        this.restClient = nvdRestClient;
        this.retryTemplate = nvdRetryTemplate;
        this.resultsPerPage = properties.resultsPerPage();
        this.requestIntervalNanos = properties.requestInterval().toNanos();
    }

    /** Fetches one page of CVEs whose last-modified time is within [from, to]. */
    public NvdPage fetchModified(Instant from, Instant to, int startIndex) {
        String fromText = NVD_DATE.format(from);
        String toText = NVD_DATE.format(to);
        return retryTemplate.execute(context -> {
            waitForTurn();
            log.info("NVD request lastModStartDate={} lastModEndDate={} startIndex={} (attempt {})",
                    fromText, toText, startIndex, context.getRetryCount() + 1);
            return restClient.get()
                    .uri(uri -> uri
                            .queryParam("lastModStartDate", fromText)
                            .queryParam("lastModEndDate", toText)
                            .queryParam("startIndex", startIndex)
                            .queryParam("resultsPerPage", resultsPerPage)
                            .build())
                    .retrieve()
                    .body(NvdPage.class);
        });
    }

    /** Sleeps until at least request-interval has passed since the previous request started. */
    private synchronized void waitForTurn() {
        if (anyRequestSent) {
            long waitNanos = requestIntervalNanos - (System.nanoTime() - lastRequestStartNanos);
            if (waitNanos > 0) {
                try {
                    Thread.sleep(Duration.ofNanos(waitNanos));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Interrupted while waiting to call NVD", e);
                }
            }
        }
        lastRequestStartNanos = System.nanoTime();
        anyRequestSent = true;
    }
}
