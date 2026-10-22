package com.giveaway.giveawaytrustengine.auth;

/**
 * Thrown by {@link RevocationChecker} when a revocation check could not be completed (Redis
 * unreachable, wrong credentials, timeout, etc) -- callers must fail CLOSED (treat as if
 * revoked / reject the request), never substitute a guessed true/false value.
 */
public class RevocationCheckUnavailableException extends RuntimeException {

    public RevocationCheckUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public RevocationCheckUnavailableException(String message) {
        super(message);
    }
}
