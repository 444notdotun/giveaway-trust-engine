package com.giveaway.giveawaytrustengine.auth;

import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Stores the {@code state -> code_verifier} mapping for an in-progress OAuth login, server-side
 * in Redis -- never in a cookie, URL, response, or log. See docs/slices/03-auth.md, Section 0,
 * "PKCE code_verifier and state: stored server-side in Redis" -- a {@code SameSite=Strict} cookie
 * cannot survive X's cross-site redirect back into {@code /auth/callback}, so this sidesteps the
 * question entirely rather than weakening a cookie's policy.
 *
 * {@code consumeVerifier} is a single atomic {@code GETDEL} -- never a {@code GET} followed by a
 * separate {@code DELETE} -- so the read and the single-use consumption cannot race: a second
 * {@code consumeVerifier} call for the same state (a replay) is guaranteed to see nothing, never
 * a window where both calls could still observe the value.
 */
public class OAuthStateService {

    private static final String STATE_KEY_PREFIX = "oauth:state:";

    private final LettuceConnectionFactory connectionFactory;
    private final Duration ttl;

    public OAuthStateService(LettuceConnectionFactory connectionFactory, Duration ttl) {
        this.connectionFactory = connectionFactory;
        this.ttl = ttl;
    }

    /** Generates a fresh, single-use state, stores its verifier with this service's TTL, returns the state. */
    public String createState(String codeVerifier) {
        String state = PkceChallenge.generateState();
        try (RedisConnection conn = connectionFactory.getConnection()) {
            conn.stringCommands().setEx(stateKey(state), ttl.toSeconds(), codeVerifier.getBytes(StandardCharsets.UTF_8));
        }
        return state;
    }

    /**
     * Atomic single-use read: {@code GETDEL}. Returns {@code null} if the state is missing,
     * unknown, or already consumed by an earlier call (replay).
     */
    public String consumeVerifier(String state) {
        try (RedisConnection conn = connectionFactory.getConnection()) {
            byte[] value = conn.stringCommands().getDel(stateKey(state));
            return value == null ? null : new String(value, StandardCharsets.UTF_8);
        }
    }

    private static byte[] stateKey(String state) {
        return (STATE_KEY_PREFIX + state).getBytes(StandardCharsets.UTF_8);
    }
}
