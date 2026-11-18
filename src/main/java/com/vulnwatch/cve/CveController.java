package com.vulnwatch.cve;

import com.vulnwatch.web.PageResponse;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;

/**
 * HTTP endpoints under {@code /api/cves}. It only translates HTTP to service calls; the constraint
 * annotations on parameters (@Pattern, @Min, @Max) are checked by Spring MVC before the method runs.
 */
@RestController
@RequestMapping("/api/cves")
public class CveController {

    private final CveService service;

    public CveController(CveService service) {
        this.service = service;
    }

    @GetMapping("/{id}")
    public CveResponse getById(
            @PathVariable @Pattern(regexp = "(?i)CVE-\\d{4}-\\d{4,}", message = "must look like CVE-2021-44228")
            String id) {
        return service.getById(id);
    }

    @GetMapping
    public PageResponse<CveResponse> list(
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) String vendor,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate publishedFrom,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate publishedTo,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        if (publishedFrom != null && publishedTo != null && publishedFrom.isAfter(publishedTo)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "publishedFrom must not be after publishedTo");
        }
        return service.list(new CveFilter(severity, vendor, publishedFrom, publishedTo), page, size);
    }
}
