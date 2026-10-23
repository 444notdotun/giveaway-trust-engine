package com.giveaway.giveawaytrustengine.auth;

/**
 * Thrown by {@link RefreshTokenService#refresh(String)} when the presented refresh token's
 * {@code expires_at} is in the past (relative to the injected {@link java.time.Clock}).
 *
 */
public class ExpiredRefreshTokenException extends RuntimeException {

    public ExpiredRefreshTokenException(String message) {
        super(message);
    }
}
