package com.giveaway.giveawaytrustengine.auth;

import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Stores the {@code state -> (code_verifier, binding-cookie hash)} mapping for an in-progress
 * OAuth login, server-side in Redis -- never in a cookie, URL, response, or log. See
 * docs/slices/03-auth.md, Section 0, "PKCE code_verifier and state: stored server-side in Redis"
 * -- a {@code SameSite=Strict} cookie cannot survive X's cross-site redirect back into
 * {@code /auth/callback}, so this sidesteps the question entirely rather than weakening a
 * cookie's policy.
 *
 * <p>The stored Redis value is {@code codeVerifier + ":" + sha256Hex(bindingNonce)} -- chunk 4
 * review item 1 added the binding-nonce hash alongside the verifier, in the SAME key with the
 * SAME TTL, so a {@code state}+{@code code} pair captured by an attacker and handed to a victim
 * (login CSRF / RFC 6749 10.12) cannot complete without also knowing the raw nonce, which only
 * ever leaves this server inside the {@code oauthBinding} cookie set on the browser that started
 * this exact login.
 *
 * <p>{@code consumeState} is a single atomic {@code GETDEL} -- never a {@code GET} followed by a
 * separate {@code DELETE} -- so the read and the single-use consumption cannot race: a second
 * {@code consumeState} call for the same state (a replay, or a wrong-cookie retry) is guaranteed
 * to see nothing, never a window where both calls could still observe the value. This also means
 * the state is burned by the FIRST call regardless of whether the binding check that follows it
 * (in {@link OAuthLoginController}) actually passes.
 */
public class OAuthStateService {

    private static final String STATE_KEY_PREFIX = "oauth:state:";
    private static final String DELIMITER = ":";

    private final LettuceConnectionFactory connectionFactory;
    private final Duration ttl;

    public OAuthStateService(LettuceConnectionFactory connectionFactory, Duration ttl) {
        this.connectionFactory = connectionFactory;
        this.ttl = ttl;
    }

    /** The state, plus the RAW binding nonce to put in the {@code oauthBinding} cookie (never the hash). */
    public record StateCreationResult(String state, String bindingNonce) {
    }

    /** The verifier, plus the hex-encoded SHA-256 hash to check an incoming cookie's nonce against. */
    public record ConsumedState(String codeVerifier, String bindingHashHex) {
    }

    /**
     * Generates a fresh, single-use state AND a fresh binding nonce; stores
     * {@code codeVerifier + ":" + sha256Hex(nonce)} under the state's key with this service's
     * TTL; returns the state (for the redirect to X) and the raw nonce (for the binding cookie).
     */
    public StateCreationResult createState(String codeVerifier) {
        String state = PkceChallenge.generateState();
        String bindingNonce = PkceChallenge.generateBindingNonce();
        String storedValue = codeVerifier + DELIMITER + PkceChallenge.sha256Hex(bindingNonce);
        try (RedisConnection conn = connectionFactory.getConnection()) {
            conn.stringCommands().setEx(stateKey(state), ttl.toSeconds(), storedValue.getBytes(StandardCharsets.UTF_8));
        }
        catch (RuntimeException redisFailure) {
            throw new OAuthStateUnavailableException("oauth state store unavailable", redisFailure);
        }
        return new StateCreationResult(state, bindingNonce);
    }

    /**
     * Atomic single-use read: {@code GETDEL}. Returns {@code null} if the state is missing,
     * unknown, or already consumed by an earlier call (replay) -- the caller still has to check
     * the returned {@code bindingHashHex} against the request's own {@code oauthBinding} cookie;
     * this method only proves the state itself was once real.
     */
    public ConsumedState consumeState(String state) {
        byte[] value;
        try (RedisConnection conn = connectionFactory.getConnection()) {
            value = conn.stringCommands().getDel(stateKey(state));
        }
        catch (RuntimeException redisFailure) {
            throw new OAuthStateUnavailableException("oauth state store unavailable", redisFailure);
        }
        if (value == null) {
            return null;
        }
        String stored = new String(value, StandardCharsets.UTF_8);
        int idx = stored.indexOf(DELIMITER);
        if (idx < 0) {
            return null;
        }
        return new ConsumedState(stored.substring(0, idx), stored.substring(idx + 1));
    }

    private static byte[] stateKey(String state) {
        return (STATE_KEY_PREFIX + state).getBytes(StandardCharsets.UTF_8);
    }
}
