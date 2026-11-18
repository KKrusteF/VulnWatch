package com.vulnwatch.nvd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.retry.RetryCallback;
import org.springframework.retry.RetryContext;
import org.springframework.retry.RetryListener;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.time.Clock;

/**
 * Creates the beans the NVD sync needs: the HTTP client, the retry policy and a clock.
 * Methods annotated with {@code @Bean} run once at startup and their return values become beans.
 */
@Configuration
@EnableScheduling
@EnableConfigurationProperties(NvdProperties.class)
public class NvdConfig {

    private static final Logger log = LoggerFactory.getLogger(NvdConfig.class);

    /** The current time. A bean, so tests can replace it with a clock they control. */
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    /** Spring Boot's builder already knows how to turn JSON into records with Boot's ObjectMapper. */
    @Bean
    RestClient nvdRestClient(RestClient.Builder builder, NvdProperties properties) {
        return createRestClient(builder, properties);
    }

    @Bean
    RetryTemplate nvdRetryTemplate(NvdProperties properties) {
        return createRetryTemplate(properties);
    }

    static RestClient createRestClient(RestClient.Builder builder, NvdProperties properties) {
        ClientHttpRequestFactorySettings timeouts = ClientHttpRequestFactorySettings.defaults()
                .withConnectTimeout(properties.connectTimeout())
                .withReadTimeout(properties.readTimeout());
        builder.baseUrl(properties.baseUrl())
                .requestFactory(ClientHttpRequestFactoryBuilder.detect().build(timeouts));
        if (properties.hasApiKey()) {
            builder.defaultHeader("apiKey", properties.apiKey());
        }
        return builder.build();
    }

    /**
     * Retries only errors that may go away on their own: 429 (rate limited), 5xx and network problems.
     * Other errors such as 400 or 404 mean the request itself is wrong, so they fail immediately.
     */
    static RetryTemplate createRetryTemplate(NvdProperties properties) {
        NvdProperties.Retry retry = properties.retry();
        return RetryTemplate.builder()
                .maxAttempts(retry.maxAttempts())
                .exponentialBackoff(retry.initialBackoff().toMillis(), retry.multiplier(),
                        retry.maxBackoff().toMillis())
                .retryOn(HttpServerErrorException.class)
                .retryOn(HttpClientErrorException.TooManyRequests.class)
                .retryOn(ResourceAccessException.class)
                .withListener(new LoggingRetryListener(retry.maxAttempts()))
                .build();
    }

    /** Logs every failed attempt, so retries are visible in the app log. */
    private record LoggingRetryListener(int maxAttempts) implements RetryListener {

        @Override
        public <T, E extends Throwable> void onError(RetryContext context, RetryCallback<T, E> callback,
                                                     Throwable throwable) {
            String reason = throwable instanceof RestClientResponseException http
                    ? "HTTP " + http.getStatusCode().value()
                    : throwable.getClass().getSimpleName() + ": " + throwable.getMessage();
            log.warn("NVD request attempt {}/{} failed: {}", context.getRetryCount(), maxAttempts, reason);
        }
    }
}
