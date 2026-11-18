package com.vulnwatch.nvd;

import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * The {@code vulnwatch.nvd.*} settings from application.yml, bound into a typed object at startup.
 * {@code @Validated} makes the app refuse to start if a value is missing or out of range.
 */
@ConfigurationProperties("vulnwatch.nvd")
@Validated
public record NvdProperties(
        boolean enabled,
        @NotBlank String baseUrl,
        String apiKey,
        @NotNull Duration pollInterval,
        @NotNull Duration initialDelay,
        @NotNull Duration initialLookback,
        @NotNull Duration overlap,
        @Min(1) @Max(2000) int resultsPerPage,
        @NotNull Duration requestInterval,
        @NotNull Duration connectTimeout,
        @NotNull Duration readTimeout,
        @Valid @NotNull Retry retry) {

    /** True when an API key is configured; NVD then allows more requests. */
    public boolean hasApiKey() {
        return apiKey != null && !apiKey.isBlank();
    }

    /** Retry settings for failed NVD requests. */
    public record Retry(
            @Min(1) int maxAttempts,
            @NotNull Duration initialBackoff,
            @DecimalMin("1.0") double multiplier,
            @NotNull Duration maxBackoff) {
    }
}
