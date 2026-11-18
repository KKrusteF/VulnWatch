package com.vulnwatch.cve;

/**
 * One row of the "top vendors" query: a vendor and how many CVEs affect it.
 */
public interface VendorCount {

    String getVendor();

    long getTotal();
}
