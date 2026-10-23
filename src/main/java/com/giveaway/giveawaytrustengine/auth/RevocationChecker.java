package com.giveaway.giveawaytrustengine.auth;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * docs/slices/03-auth.md, Section 4 (revocation ordering -- CRITICAL REVIEW).
 *
 * {@code revokeFamily}: database commit first (every {@code refresh_token} row in the family
 * marked {@code used = true}), then the Redis write. If the database write itself fails, this
 * throws before Redis is ever touched -- Redis genuinely stays untouched, not just "untouched in
 * this one test run". If the database write succeeds and the SUBSEQUENT Redis write fails, this
 * still throws (fails closed -- the caller must not treat this as success), but the database
 * revocation has already committed and survives regardless of what happens to Redis next.
 *
 * {@code isFamilyRevoked}: checks the direct evidence -- the TTL'd {@code revoked:{familyId}}
 * key -- and nothing else. {@code clock}/{@code tokenIssuedAt} remain parameters for API
 * stability even though this class no longer uses either internally; a revocation-epoch
 * fallback (tracking a Redis data-loss event so an already-revoked-but-now-evidence-free token
 * couldn't silently pass) was built, reviewed, and deliberately cut as a scope reduction -- see
 * docs/slices/03-auth.md, Section 4a, "Accepted risk: Redis data loss within the revocation TTL
 * window" for the accepted risk this leaves and why it's still bounded.
 *
 * Any Redis failure (unreachable, wrong credentials, timeout) is wrapped as
 * {@link RevocationCheckUnavailableException} -- the cause chain is Lettuce's own exception,
 * which this class never augments with the password or connection string (those were never
 * passed to this class as values to include in a message; they live only inside the
 * {@link LettuceConnectionFactory} already configured before this class ever sees it).
 */
public class RevocationChecker {

    private static final Logger log = LoggerFactory.getLogger(RevocationChecker.class);

    private static final String REVOKED_KEY_PREFIX = "revoked:";
    private static final String REDIS_WRITE_FAILED_AFTER_DB_COMMIT_COUNTER =
            "giveaway.revocation.redis.write.failed.after.db.commit";
    /** Chunk 4 review, item 1: one counter, tagged by reason, for every auth failure path. */
    private static final String FAILURE_COUNTER_NAME = "giveaway.auth.failure";

    private final DataSource dataSource;
    private final LettuceConnectionFactory connectionFactory;
    private final Duration revokedKeyTtl;
    private final MeterRegistry meterRegistry;

    public RevocationChecker(DataSource dataSource, LettuceConnectionFactory connectionFactory,
            Clock clock, Duration revokedKeyTtl) {
        this(dataSource, connectionFactory, clock, revokedKeyTtl, new SimpleMeterRegistry());
    }

    public RevocationChecker(DataSource dataSource, LettuceConnectionFactory connectionFactory,
            Clock clock, Duration revokedKeyTtl, MeterRegistry meterRegistry) {
        this.dataSource = dataSource;
        this.connectionFactory = connectionFactory;
        this.revokedKeyTtl = revokedKeyTtl;
        this.meterRegistry = meterRegistry;
    }

    public boolean isFamilyRevoked(UUID familyId, Instant tokenIssuedAt) {
        boolean revoked;
        try (RedisConnection conn = connectionFactory.getConnection()) {
            revoked = Boolean.TRUE.equals(conn.keyCommands().exists(revokedKey(familyId)));
        }
        catch (RuntimeException redisFailure) {
            // familyId only, never a token or secret -- same discipline as revokeFamily below.
            log.warn("resolve revocation check rejected: reason=redis-unavailable familyId={}", familyId);
            meterRegistry.counter(FAILURE_COUNTER_NAME, "reason", "redis-unavailable").increment();
            throw new RevocationCheckUnavailableException("revocation check could not be completed", redisFailure);
        }
        if (revoked) {
            log.warn("resolve revocation check rejected: reason=revoked familyId={}", familyId);
            meterRegistry.counter(FAILURE_COUNTER_NAME, "reason", "revoked").increment();
        }
        return revoked;
    }

    public void revokeFamily(UUID familyId) {
        // Database first -- committed and durable before Redis is ever touched.
        markFamilyUsedInDatabase(familyId);

        try (RedisConnection conn = connectionFactory.getConnection()) {
            conn.stringCommands().setEx(revokedKey(familyId), revokedKeyTtl.toSeconds(), new byte[] {1});
        }
        catch (RuntimeException redisFailure) {
            // The DB write above already committed -- this failure is reported (fail closed,
            // never silently swallowed) but does not and cannot undo that commit. Logged and
            // counted so this residual-window event (docs/slices/03-auth.md Section 4's table)
            // is operator-visible, not just a fact on paper -- familyId only, never a token,
            // hash, or secret.
            log.warn("database revocation committed but redis write failed: familyId={}", familyId);
            meterRegistry.counter(REDIS_WRITE_FAILED_AFTER_DB_COMMIT_COUNTER).increment();
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

    private static byte[] revokedKey(UUID familyId) {
        return (REVOKED_KEY_PREFIX + familyId).getBytes(StandardCharsets.UTF_8);
    }
}
