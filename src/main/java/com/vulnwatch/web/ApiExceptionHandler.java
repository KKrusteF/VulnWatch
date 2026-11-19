package com.vulnwatch.web;

import com.vulnwatch.cve.CveNotFoundException;
import com.vulnwatch.search.SearchUnavailableException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.List;

/**
 * Turns exceptions from any controller into RFC 9457 "problem detail" JSON responses.
 * The base class already handles Spring MVC's own errors (bad parameter types, unknown routes, ...).
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(CveNotFoundException.class)
    public ProblemDetail handleCveNotFound(CveNotFoundException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND,
                "No CVE with ID " + ex.getId() + " is stored in VulnWatch.");
        problem.setTitle("CVE not found");
        return problem;
    }

    /** Elasticsearch is down: search cannot answer, but the rest of the API (backed by Postgres) still works. */
    @ExceptionHandler(SearchUnavailableException.class)
    public ProblemDetail handleSearchUnavailable(SearchUnavailableException ex) {
        logger.warn(ex.getMessage());
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE,
                "Search is temporarily unavailable. Try again later, or use /api/cves to list CVEs.");
        problem.setTitle("Search unavailable");
        return problem;
    }

    /** Adds a readable list of failed constraints, e.g. "size: must be less than or equal to 100". */
    @Override
    protected ResponseEntity<Object> handleHandlerMethodValidationException(
            HandlerMethodValidationException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<String> errors = ex.getParameterValidationResults().stream()
                .flatMap(result -> result.getResolvableErrors().stream()
                        .map(error -> result.getMethodParameter().getParameterName() + ": " + error.getDefaultMessage()))
                .toList();
        ex.getBody().setProperty("errors", errors);
        return handleExceptionInternal(ex, ex.getBody(), headers, status, request);
    }
}
