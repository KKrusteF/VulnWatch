package com.vulnwatch.nvd;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.time.Instant;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests {@link NvdClient} against a fake NVD (WireMock) without starting Spring. The client is built
 * with the same factory methods the app uses, so the real retry rules are tested.
 */
class NvdClientTest {

    private static final String PATH = "/rest/json/cves/2.0";
    private static final String EMPTY_PAGE =
            "{\"resultsPerPage\": 0, \"startIndex\": 0, \"totalResults\": 0, \"vulnerabilities\": []}";
    private static final int MAX_ATTEMPTS = 3;

    @RegisterExtension
    static WireMockExtension nvd = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .build();

    @Test
    void sendsTimeWindowAndPagingAsQueryParameters() {
        nvd.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson(
                "{\"resultsPerPage\": 0, \"startIndex\": 4000, \"totalResults\": 4321, \"vulnerabilities\": []}")));

        NvdPage page = client("", Duration.ZERO).fetchModified(
                Instant.parse("2024-01-01T00:00:00Z"), Instant.parse("2024-01-02T12:34:56.789Z"), 4000);

        assertThat(page.totalResults()).isEqualTo(4321);
        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH))
                .withQueryParam("lastModStartDate", equalTo("2024-01-01T00:00:00.000Z"))
                .withQueryParam("lastModEndDate", equalTo("2024-01-02T12:34:56.789Z"))
                .withQueryParam("startIndex", equalTo("4000"))
                .withQueryParam("resultsPerPage", equalTo("2000")));
    }

    @Test
    void sendsApiKeyHeaderWhenConfigured() {
        nvd.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson(EMPTY_PAGE)));

        client("secret-key", Duration.ZERO).fetchModified(Instant.EPOCH, Instant.EPOCH.plusSeconds(60), 0);

        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH)).withHeader("apiKey", equalTo("secret-key")));
    }

    @Test
    void sendsNoApiKeyHeaderWhenBlank() {
        nvd.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson(EMPTY_PAGE)));

        client("", Duration.ZERO).fetchModified(Instant.EPOCH, Instant.EPOCH.plusSeconds(60), 0);

        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH)).withoutHeader("apiKey"));
    }

    @Test
    void retriesRateLimitAndServerErrorsUntilSuccess() {
        nvd.stubFor(get(urlPathEqualTo(PATH)).inScenario("flaky").whenScenarioStateIs(STARTED)
                .willReturn(aResponse().withStatus(429)).willSetStateTo("rate limited"));
        nvd.stubFor(get(urlPathEqualTo(PATH)).inScenario("flaky").whenScenarioStateIs("rate limited")
                .willReturn(aResponse().withStatus(503)).willSetStateTo("recovered"));
        nvd.stubFor(get(urlPathEqualTo(PATH)).inScenario("flaky").whenScenarioStateIs("recovered")
                .willReturn(okJson(EMPTY_PAGE)));

        NvdPage page = client("", Duration.ZERO).fetchModified(Instant.EPOCH, Instant.EPOCH.plusSeconds(60), 0);

        assertThat(page.totalResults()).isZero();
        nvd.verify(3, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void givesUpAfterMaxAttemptsOnPermanentServerError() {
        nvd.stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(500)));
        NvdClient client = client("", Duration.ZERO);

        assertThatThrownBy(() -> client.fetchModified(Instant.EPOCH, Instant.EPOCH.plusSeconds(60), 0))
                .isInstanceOf(HttpServerErrorException.class);
        nvd.verify(MAX_ATTEMPTS, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void doesNotRetryOtherClientErrors() {
        nvd.stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(404)));
        NvdClient client = client("", Duration.ZERO);

        assertThatThrownBy(() -> client.fetchModified(Instant.EPOCH, Instant.EPOCH.plusSeconds(60), 0))
                .isInstanceOf(HttpClientErrorException.NotFound.class);
        nvd.verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void keepsRequestsAtLeastRequestIntervalApart() {
        nvd.stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson(EMPTY_PAGE)));
        Duration interval = Duration.ofMillis(300);
        NvdClient client = client("", interval);

        long start = System.nanoTime();
        client.fetchModified(Instant.EPOCH, Instant.EPOCH.plusSeconds(60), 0);
        client.fetchModified(Instant.EPOCH, Instant.EPOCH.plusSeconds(60), 0);
        Duration elapsed = Duration.ofNanos(System.nanoTime() - start);

        assertThat(elapsed).isGreaterThanOrEqualTo(interval);
        nvd.verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    private NvdClient client(String apiKey, Duration requestInterval) {
        NvdProperties properties = new NvdProperties(
                true, nvd.baseUrl() + PATH, apiKey,
                Duration.ofHours(2), Duration.ofSeconds(10), Duration.ofDays(7), Duration.ofMinutes(5),
                2000, requestInterval, Duration.ofSeconds(5), Duration.ofSeconds(5),
                new NvdProperties.Retry(MAX_ATTEMPTS, Duration.ofMillis(1), 2, Duration.ofMillis(5)));
        return new NvdClient(
                NvdConfig.createRestClient(RestClient.builder(), properties),
                NvdConfig.createRetryTemplate(properties),
                properties);
    }
}
