package com.giveaway.giveawaytrustengine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Typed shape for {@code app.x-oauth.*} config -- X's OAuth2/PKCE login flow. See
 * docs/slices/03-auth.md, Section 0. Property names are fixed by {@code OAuthLoginFlowTest}'s
 * own command-line arguments; do not rename.
 */
@ConfigurationProperties(prefix = "app.x-oauth")
public record XOAuthProperties(
        String clientId,
        String clientSecret,
        String redirectUri,
        String authorizeUrl,
        String tokenUrl,
        String userLookupUrl,
        Duration connectTimeout,
        Duration requestTimeout) {
}
