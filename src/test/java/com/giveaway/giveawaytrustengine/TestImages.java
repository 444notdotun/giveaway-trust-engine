package com.giveaway.giveawaytrustengine;

/**
 * Shared Testcontainers image tags, pinned to the same major version as docker-compose.yaml
 * so test behavior tracks the version actually run in dev/staging/production.
 */
public final class TestImages {

    public static final String POSTGRES = "postgres:17-alpine";

    private TestImages() {
    }
}
