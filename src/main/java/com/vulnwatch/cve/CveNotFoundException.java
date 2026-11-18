package com.vulnwatch.cve;

/**
 * Thrown when a CVE ID is not in the database. Turned into a 404 by the API exception handler.
 */
public class CveNotFoundException extends RuntimeException {

    private final String id;

    public CveNotFoundException(String id) {
        super("CVE " + id + " was not found");
        this.id = id;
    }

    public String getId() {
        return id;
    }
}
