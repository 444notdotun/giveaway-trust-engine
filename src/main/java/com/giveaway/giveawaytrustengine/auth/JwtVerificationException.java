package com.giveaway.giveawaytrustengine.auth;

/**
 * Thrown by {@link JwtService#verifyAccessToken(String)} when a token fails verification for
 * any reason (expired, tampered signature, algorithm confusion, not yet implemented, etc).
 * {@link #reason()} is a short machine-readable code, never the raw token or signing key.
 *
 * RED stub (slice 3): {@link JwtService#verifyAccessToken(String)} currently always throws this
 * with reason {@code "not-implemented"}, regardless of the token's actual shape.
 */
public class JwtVerificationException extends RuntimeException {

    private final String reason;

    public JwtVerificationException(String reason) {
        super(reason);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
