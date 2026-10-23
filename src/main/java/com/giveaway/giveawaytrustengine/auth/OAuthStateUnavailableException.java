package com.giveaway.giveawaytrustengine.auth;

/**
 * Thrown by {@link OAuthStateService} when Redis (the server-side store for the state, PKCE
 * verifier, and binding-cookie hash) could not be reached -- callers must fail CLOSED (a clean
 * 503), never substitute a guessed outcome. Same category of exception as
 * {@link RevocationCheckUnavailableException}, scoped to the OAuth login flow instead of
 * revocation checks.
 */
public class OAuthStateUnavailableException extends RuntimeException {

    public OAuthStateUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
