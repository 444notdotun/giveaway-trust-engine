package com.giveaway.giveawaytrustengine.auth;

/**
 * Thrown by {@link XOAuthClient} when either X call (token exchange, user lookup) fails for any
 * reason -- timeout, connection failure, a non-2xx response, or a response missing the field this
 * app needs. The message is always a short, fixed, generic description; it never embeds the
 * response body, the access token, or the client secret (CLAUDE.md: never log/return sensitive
 * values -- the same discipline {@code RefreshTokenService}'s {@code GENERIC_REJECTION_MESSAGE}
 * already applies to refresh tokens applies here to X's own tokens and credentials).
 */
public class OAuthExchangeException extends RuntimeException {

    public OAuthExchangeException(String message) {
        super(message);
    }

    public OAuthExchangeException(String message, Throwable cause) {
        super(message, cause);
    }
}
