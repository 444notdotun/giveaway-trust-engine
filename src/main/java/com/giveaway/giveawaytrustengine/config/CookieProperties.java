package com.giveaway.giveawaytrustengine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Typed shape for {@code app.cookie.*} config -- the session cookies set after a successful
 * OAuth login. See docs/slices/03-auth.md, Section 3. {@code path} and the two {@code Max-Age}
 * values come from configuration, never hardcoded in the controller that sets them.
 */
@ConfigurationProperties(prefix = "app.cookie")
public record CookieProperties(String path, Duration accessTokenMaxAge, Duration refreshTokenMaxAge) {
}
