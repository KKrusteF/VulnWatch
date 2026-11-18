package com.vulnwatch.cve;

import com.vulnwatch.web.PageResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Read-side business logic for CVEs. Every public method runs in a read-only transaction,
 * so lazy data such as vendors can still be loaded while the entity is converted to a response.
 */
@Service
@Transactional(readOnly = true)
public class CveService {

    private static final Sort NEWEST_FIRST = Sort.by(Sort.Order.desc("publishedAt"), Sort.Order.desc("id"));

    private final CveRepository repository;

    // Constructor injection: Spring sees the parameter and passes in the CveRepository bean.
    public CveService(CveRepository repository) {
        this.repository = repository;
    }

    public CveResponse getById(String id) {
        String normalizedId = id.toUpperCase(Locale.ROOT);
        return repository.findById(normalizedId)
                .map(CveResponse::from)
                .orElseThrow(() -> new CveNotFoundException(normalizedId));
    }

    public PageResponse<CveResponse> list(CveFilter filter, int page, int size) {
        Page<Cve> result = repository.findAll(
                CveSpecifications.matching(filter), PageRequest.of(page, size, NEWEST_FIRST));
        return PageResponse.from(result.map(CveResponse::from));
    }

    /** Loads the stored CVEs with these IDs; IDs that are not stored are skipped. */
    public List<CveResponse> getByIds(Collection<String> ids) {
        return repository.findAllById(ids).stream()
                .map(CveResponse::from)
                .toList();
    }
}
