package com.giveaway.giveawaytrustengine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Typed shape for {@code app.cookie.*} config -- the session cookies set after a successful
 * OAuth login. See docs/slices/03-auth.md, Section 3. {@code path}, {@code refreshTokenPath},
 * and the two {@code Max-Age} values come from configuration, never hardcoded in the controller
 * that sets them.
 *
 * <p>{@code path} ({@code "/"}) scopes the access cookie -- every authenticated endpoint reads
 * it. {@code refreshTokenPath} ({@code "/auth/refresh"}, chunk 4 review item 3) scopes the
 * refresh cookie narrowly to the one endpoint that will ever read it -- there is no reason for
 * the browser to send a refresh-token-bearing cookie on every other authenticated request, and
 * narrowing its scope is free defense in depth against it leaking via an unrelated endpoint's
 * logging, a proxy, or a browser extension that can see all cookies sent on the current page.
 */
@ConfigurationProperties(prefix = "app.cookie")
public record CookieProperties(String path, String refreshTokenPath, Duration accessTokenMaxAge,
        Duration refreshTokenMaxAge) {
}
