package com.giveaway.giveawaytrustengine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed shape for {@code app.*} config, bound after {@link StartupGuardBeanFactoryPostProcessor}
 * has already approved the environment/Bachs-mode combination. Deliberately carries no Jakarta
 * Bean Validation annotations -- see docs/slices/02-startup-guard-and-typed-config.md,
 * "AppProperties binding test, and the deviation from CLAUDE.md" for why required-ness is
 * enforced by the guard instead.
 *
 * {@code bachs.baseUrl} is the only field any client is ever allowed to call; sandboxBaseUrl and
 * liveBaseUrl exist only for the guard's own classification.
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(Environment environment, BachsProperties bachs) {

    public record BachsProperties(String sandboxBaseUrl, String liveBaseUrl, String baseUrl) {
    }
}
