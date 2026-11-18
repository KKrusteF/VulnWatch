package com.vulnwatch.web;

import org.springframework.data.domain.Page;

import java.util.List;

/**
 * A stable JSON shape for one page of results. Spring's own {@code Page} JSON is not
 * guaranteed to stay the same between versions, so the API returns this instead.
 */
public record PageResponse<T>(List<T> items, int page, int size, long totalItems, int totalPages) {

    public static <T> PageResponse<T> from(Page<T> page) {
        return new PageResponse<>(
                page.getContent(), page.getNumber(), page.getSize(), page.getTotalElements(), page.getTotalPages());
    }
}
