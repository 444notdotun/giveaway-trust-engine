package com.giveaway.giveawaytrustengine.config;

/**
 * Deployment tier. Bound from {@code app.environment}, no default value (CLAUDE.md: never
 * guess which rail is in effect). See docs/slices/02-startup-guard-and-typed-config.md.
 */
public enum Environment {
    DEV,
    STAGING,
    PRODUCTION
}
