package com.giveaway.giveawaytrustengine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed shape for {@code app.jwt.*} config. See docs/slices/03-auth.md, Section 2.
 * {@code signingKey} is validated at startup by
 * {@link JwtSigningKeyGuardBeanFactoryPostProcessor} before this record is ever bound.
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(String signingKey) {
}
