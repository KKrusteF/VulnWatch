package com.vulnwatch.search;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.FieldValue;
import co.elastic.clients.elasticsearch._types.SortOrder;
import co.elastic.clients.elasticsearch._types.query_dsl.Operator;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.elasticsearch.core.SearchResponse;
import co.elastic.clients.elasticsearch.core.search.Hit;
import com.vulnwatch.cve.CveFilter;
import com.vulnwatch.cve.CveResponse;
import com.vulnwatch.web.PageResponse;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Full-text search on CVE descriptions in Elasticsearch, combined with exact filters.
 * The text query decides the relevance score; the filters only include or exclude documents.
 */
@Service
public class CveSearchService {

    private final ElasticsearchClient client;
    private final String indexName;

    public CveSearchService(ElasticsearchClient client, SearchProperties properties) {
        this.client = client;
        this.indexName = properties.indexName();
    }

    public PageResponse<CveResponse> search(String q, CveFilter filter, int page, int size) {
        // "must": scored full-text match. simple_query_string supports "quoted phrases" and never throws
        // on bad syntax; AND means every word has to appear.
        Query text = Query.of(query -> query.simpleQueryString(s -> s
                .query(q)
                .fields("description")
                .defaultOperator(Operator.And)));

        // "filter": yes/no conditions. They do not change the score and Elasticsearch can cache them.
        List<Query> filters = new ArrayList<>();
        if (filter.severity() != null) {
            filters.add(Query.of(query -> query.term(t -> t
                    .field("severity").value(FieldValue.of(filter.severity().name())))));
        }
        if (filter.vendor() != null && !filter.vendor().isBlank()) {
            String vendor = filter.vendor().trim().toLowerCase(Locale.ROOT);
            filters.add(Query.of(query -> query.term(t -> t.field("vendors").value(FieldValue.of(vendor)))));
        }
        if (filter.publishedFrom() != null || filter.publishedTo() != null) {
            String from = filter.publishedFrom() == null ? null
                    : filter.publishedFrom().atStartOfDay(ZoneOffset.UTC).toInstant().toString();
            String toExclusive = filter.publishedTo() == null ? null
                    : filter.publishedTo().plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant().toString();
            filters.add(Query.of(query -> query.range(r -> r.date(d -> {
                d.field("publishedAt");
                if (from != null) {
                    d.gte(from);
                }
                if (toExclusive != null) {
                    d.lt(toExclusive);
                }
                return d;
            }))));
        }

        SearchResponse<CveDocument> response;
        try {
            response = client.search(s -> s
                            .index(indexName)
                            .query(query -> query.bool(b -> b.must(text).filter(filters)))
                            // Most relevant first; newest and then ID break ties so paging is stable.
                            .sort(so -> so.score(sc -> sc.order(SortOrder.Desc)))
                            .sort(so -> so.field(f -> f.field("publishedAt").order(SortOrder.Desc)))
                            .sort(so -> so.field(f -> f.field("id").order(SortOrder.Desc)))
                            .from(page * size)
                            .size(size)
                            // Count every match exactly; by default Elasticsearch stops counting at 10,000.
                            .trackTotalHits(t -> t.enabled(true)),
                    CveDocument.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Search request to Elasticsearch failed", e);
        }

        List<CveResponse> items = response.hits().hits().stream()
                .map(Hit::source)
                .filter(Objects::nonNull)
                .map(CveDocument::toResponse)
                .toList();
        long total = response.hits().total() == null ? items.size() : response.hits().total().value();
        int totalPages = (int) ((total + size - 1) / size);
        return new PageResponse<>(items, page, size, total, totalPages);
    }
}
