package com.vulnwatch.search;

import co.elastic.clients.elasticsearch._types.ElasticsearchException;

import java.io.IOException;

/**
 * Elasticsearch cannot be reached or is overloaded right now. This is temporary: the same request
 * is expected to work later, so callers retry it instead of giving up.
 */
public class SearchUnavailableException extends RuntimeException {

    public SearchUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    /** Wraps a network error (Elasticsearch down or unreachable). */
    static SearchUnavailableException from(String action, IOException cause) {
        return new SearchUnavailableException(action + " failed: Elasticsearch is not reachable", cause);
    }

    /**
     * Turns 5xx and 429 answers into this exception and returns any other error unchanged,
     * because a 4xx answer means the request itself is wrong and retrying will not help.
     */
    static RuntimeException classify(String action, ElasticsearchException cause) {
        int status = cause.status();
        if (status >= 500 || status == 429) {
            return new SearchUnavailableException(action + " failed: Elasticsearch answered " + status, cause);
        }
        return cause;
    }
}
