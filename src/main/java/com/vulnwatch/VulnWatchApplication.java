package com.vulnwatch;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point of VulnWatch. {@code @SpringBootApplication} turns on auto-configuration and
 * scans this package (and sub-packages) for components such as controllers and services.
 */
@SpringBootApplication
public class VulnWatchApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnWatchApplication.class, args);
    }
}
