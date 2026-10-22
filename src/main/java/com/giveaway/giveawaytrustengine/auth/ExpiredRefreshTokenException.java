package com.giveaway.giveawaytrustengine.auth;

/**
 * Thrown by {@link RefreshTokenService#refresh(String)} when the presented refresh token's
 * {@code expires_at} is in the past (relative to the injected {@link java.time.Clock}).
 *
 * RED stub (slice 3): no logic references this type yet -- {@link RefreshTokenService#refresh}
 * always throws {@link UnsupportedOperationException} regardless of expiry. Real expiry checking
 * is not implemented yet.
 */
public class ExpiredRefreshTokenException extends RuntimeException {

    public ExpiredRefreshTokenException(String message) {
        super(message);
    }
}
