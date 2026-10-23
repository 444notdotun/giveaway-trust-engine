package com.giveaway.giveawaytrustengine.auth;

/**
 * Thrown by {@link RefreshTokenService#refresh(String)} when a refresh token that was already
 * used (rotated) is presented again -- refresh-token reuse, triggering whole-family revocation.
 */
public class ReuseDetectedException extends RuntimeException {

    public ReuseDetectedException(String message) {
        super(message);
    }
}
