package com.vulnwatch.search;

import com.vulnwatch.cve.CveFilter;
import com.vulnwatch.cve.CveResponse;
import com.vulnwatch.cve.Severity;
import com.vulnwatch.web.PageResponse;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;

/**
 * HTTP endpoint {@code GET /api/cves/search}: full-text search on descriptions with optional filters.
 * Spring MVC prefers this literal path over the {@code /api/cves/{id}} pattern, so "search" is never
 * treated as a CVE ID.
 */
@RestController
public class CveSearchController {

    /** Elasticsearch refuses from + size above this (index.max_result_window). */
    static final int MAX_RESULT_WINDOW = 10_000;

    private final CveSearchService service;

    public CveSearchController(CveSearchService service) {
        this.service = service;
    }

    @GetMapping("/api/cves/search")
    public PageResponse<CveResponse> search(
            @RequestParam @NotBlank String q,
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) String vendor,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate publishedFrom,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate publishedTo,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        if (publishedFrom != null && publishedTo != null && publishedFrom.isAfter(publishedTo)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "publishedFrom must not be after publishedTo");
        }
        if ((long) page * size + size > MAX_RESULT_WINDOW) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "page and size go past the Elasticsearch "
                    + "result window of " + MAX_RESULT_WINDOW + " results; use the list endpoint or narrower filters");
        }
        return service.search(q, new CveFilter(severity, vendor, publishedFrom, publishedTo), page, size);
    }
}
