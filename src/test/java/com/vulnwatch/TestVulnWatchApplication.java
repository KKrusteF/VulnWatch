package com.vulnwatch;

import org.springframework.boot.SpringApplication;

/**
 * Runs the real application against a Testcontainers Postgres, without Docker Compose.
 * Start it with {@code ./gradlew bootTestRun}.
 */
public class TestVulnWatchApplication {

    public static void main(String[] args) {
        SpringApplication.from(VulnWatchApplication::main)
                .with(TestcontainersConfiguration.class)
                .run(args);
    }
}
