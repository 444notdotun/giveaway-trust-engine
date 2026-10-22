package com.giveaway.giveawaytrustengine;

/**
 * Shared Testcontainers image tags, pinned to the same major version as docker-compose.yaml
 * so test behavior tracks the version actually run in dev/staging/production.
 */
public final class TestImages {

    public static final String POSTGRES = "postgres:17-alpine";

    /** Pinned to docker-compose.yaml's local Redis version (slice 3, Section 1). */
    public static final String REDIS = "redis:7.4";

    private TestImages() {
    }
}
