package com.vulnwatch.stats;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP endpoint {@code GET /api/stats}.
 */
@RestController
public class StatsController {

    private final StatsService service;

    public StatsController(StatsService service) {
        this.service = service;
    }

    @GetMapping("/api/stats")
    public StatsResponse stats(@RequestParam(defaultValue = "10") @Min(1) @Max(100) int topVendors) {
        return service.getStats(topVendors);
    }
}
