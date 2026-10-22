package com.giveaway.giveawaytrustengine.auth;

import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Checks whether a refresh-token family has been revoked, and revokes one. See
 * docs/slices/03-auth.md, Section 4 (revocation) and Section 4a (revocation-epoch).
 *
 * Constructor shape is shared by {@code RefreshTokenConcurrencyTest} and
 * {@code RevocationCheckerTest}: {@code RevocationChecker(LettuceConnectionFactory, Clock,
 * Duration)}. {@code RefreshTokenConcurrencyTest} passes a {@code null} connection factory --
 * this RED stub never dereferences it, so that is safe for now.
 *
 * RED stub (slice 3): never actually talks to Redis. {@link #isFamilyRevoked(UUID, Instant)}
 * always returns {@code false}; {@link #revokeFamily(UUID)} is a no-op. Real Redis I/O,
 * fail-closed error handling (-> {@link RevocationCheckUnavailableException}), and the
 * revocation-epoch mechanism are not implemented yet.
 */
public class RevocationChecker {

    private final LettuceConnectionFactory connectionFactory;
    private final Clock clock;
    private final Duration epochWindow;

    public RevocationChecker(LettuceConnectionFactory connectionFactory, Clock clock, Duration epochWindow) {
        this.connectionFactory = connectionFactory;
        this.clock = clock;
        this.epochWindow = epochWindow;
    }

    public boolean isFamilyRevoked(UUID familyId, Instant tokenIssuedAt) {
        return false;
    }

    public void revokeFamily(UUID familyId) {
        // not implemented yet
    }
}
