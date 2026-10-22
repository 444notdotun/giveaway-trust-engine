package com.giveaway.giveawaytrustengine.auth;

import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Checks whether a refresh-token family has been revoked, and revokes one. See
 * docs/slices/03-auth.md, Section 4 (revocation ordering -- CRITICAL REVIEW) and Section 4a
 * (revocation-epoch).
 *
 * {@code revokeFamily}: database commit first (every {@code refresh_token} row in the family
 * marked {@code used = true}), then the Redis write. If the database write itself fails, this
 * throws before Redis is ever touched -- Redis genuinely stays untouched, not just "untouched in
 * this one test run". If the database write succeeds and the SUBSEQUENT Redis write fails, this
 * still throws (fails closed -- the caller must not treat this as success), but the database
 * revocation has already committed and survives regardless of what happens to Redis next. See
 * the plan doc's own reasoning for why this ordering, not the reverse, is the one with no
 * correctness benefit the other way around.
 *
 * {@code isFamilyRevoked}: checks the direct evidence (the TTL'd {@code revoked:{familyId}} key)
 * first; if absent, falls back to the revocation-epoch check (Section 4a) -- a token issued
 * before the current epoch marker is treated as unverifiable (and thus revoked) rather than
 * silently trusted, protecting against a Redis data loss that wiped the direct evidence without
 * this app ever being told about it.
 *
 * Any Redis failure (unreachable, wrong credentials, timeout) on either path is wrapped as
 * {@link RevocationCheckUnavailableException} -- the cause chain is Lettuce's own exception,
 * which this class never augments with the password or connection string (those were never
 * passed to this class as values to include in a message; they live only inside the
 * {@link LettuceConnectionFactory} already configured before this class ever sees it).
 */
public class RevocationChecker {

    private static final String REVOKED_KEY_PREFIX = "revoked:";
    private static final String EPOCH_KEY = "revocation-epoch";

    private final DataSource dataSource;
    private final LettuceConnectionFactory connectionFactory;
    private final Clock clock;
    private final Duration epochWindow;

    public RevocationChecker(DataSource dataSource, LettuceConnectionFactory connectionFactory,
            Clock clock, Duration epochWindow) {
        this.dataSource = dataSource;
        this.connectionFactory = connectionFactory;
        this.clock = clock;
        this.epochWindow = epochWindow;
    }

    public boolean isFamilyRevoked(UUID familyId, Instant tokenIssuedAt) {
        try (RedisConnection conn = connectionFactory.getConnection()) {
            byte[] revokedKey = revokedKey(familyId);
            if (Boolean.TRUE.equals(conn.keyCommands().exists(revokedKey))) {
                return true;
            }

            Instant epoch = readOrInitEpoch(conn);
            return tokenIssuedAt.isBefore(epoch);
        }
        catch (RuntimeException redisFailure) {
            throw new RevocationCheckUnavailableException("revocation check could not be completed", redisFailure);
        }
    }

    public void revokeFamily(UUID familyId) {
        // Database first -- committed and durable before Redis is ever touched.
        markFamilyUsedInDatabase(familyId);

        try (RedisConnection conn = connectionFactory.getConnection()) {
            conn.stringCommands().setEx(revokedKey(familyId), epochWindow.toSeconds(), new byte[] {1});
        }
        catch (RuntimeException redisFailure) {
            // The DB write above already committed -- this failure is reported (fail closed,
            // never silently swallowed) but does not and cannot undo that commit.
            throw new RevocationCheckUnavailableException(
                    "database revocation committed, but the Redis write failed", redisFailure);
        }
    }

    private void markFamilyUsedInDatabase(UUID familyId) {
        try (Connection conn = dataSource.getConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "UPDATE refresh_token SET used = true WHERE family_id = ?")) {
            ps.setObject(1, familyId);
            ps.executeUpdate();
        }
        catch (SQLException dbFailure) {
            throw new IllegalStateException("failed to revoke family in the database", dbFailure);
        }
    }

    /**
     * Reads the current revocation-epoch marker, or initializes it to now if absent (the
     * absence itself is the signal that Redis just lost all its prior data -- see Section 4a).
     * {@code SETNX} is used so a race between concurrent callers all discovering the absence at
     * once still converges on a single epoch value already present in Redis by the time any of
     * them reads it back, rather than each caller trusting its own local attempt blindly.
     */
    private Instant readOrInitEpoch(RedisConnection conn) {
        byte[] epochKey = EPOCH_KEY.getBytes(StandardCharsets.UTF_8);
        byte[] existing = conn.stringCommands().get(epochKey);
        if (existing != null) {
            return parseEpoch(existing);
        }
        byte[] candidate = String.valueOf(clock.instant().toEpochMilli()).getBytes(StandardCharsets.UTF_8);
        conn.stringCommands().setNX(epochKey, candidate);
        byte[] afterInit = conn.stringCommands().get(epochKey);
        return parseEpoch(afterInit);
    }

    private static Instant parseEpoch(byte[] value) {
        return Instant.ofEpochMilli(Long.parseLong(new String(value, StandardCharsets.UTF_8)));
    }

    private static byte[] revokedKey(UUID familyId) {
        return (REVOKED_KEY_PREFIX + familyId).getBytes(StandardCharsets.UTF_8);
    }
}
