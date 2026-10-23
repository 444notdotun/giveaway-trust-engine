package com.giveaway.giveawaytrustengine.auth;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisStringCommands;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.types.Expiration;

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
 * revocation has already committed and survives regardless of what happens to Redis next.
 *
 * {@code isFamilyRevoked}: checks the direct evidence (the TTL'd {@code revoked:{familyId}} key)
 * first; if absent, falls back to the revocation-epoch check (Section 4a) -- a token issued
 * before the current epoch marker is treated as unverifiable (and thus revoked) rather than
 * silently trusted, protecting against a Redis data loss that wiped the direct evidence without
 * this app ever being told about it.
 *
 * <p><b>The revocation-epoch key uses a sliding TTL, refreshed on every successful read, not a
 * plain fixed expiry.</b> The epoch marker must eventually expire too -- CLAUDE.md: "every Redis
 * key has a TTL" -- but it may only ever lapse at a moment when no access token issued "against"
 * it could still be alive. If the epoch key simply expired on a fixed schedule regardless of
 * traffic, the very next check after that expiry would re-initialize the epoch to "now", which
 * would make every still-valid, already-issued access token (anything with an {@code iat} before
 * that instant) read as "issued before the epoch" -- i.e. revoked -- even though nothing about
 * those sessions was ever actually revoked. That would silently log out every active CM session
 * network-wide on a timer, which is a far worse failure mode than the one this mechanism exists
 * to guard against. Refreshing the TTL on every read means the key only expires during a
 * genuinely idle stretch with zero revocation checks for the full {@code epochTtl} duration --
 * and {@code epochTtl} is required (constructor-validated) to be at least twice the access-token
 * lifetime ({@code epochWindow}), so by the time that much silence has passed, any token that
 * could still have been "live" relative to the old epoch has already expired on its own merits
 * anyway. Losing the epoch at that point is harmless: there is no live session left for a reset
 * epoch to wrongly catch.
 *
 * Any Redis failure (unreachable, wrong credentials, timeout) on either path is wrapped as
 * {@link RevocationCheckUnavailableException} -- the cause chain is Lettuce's own exception,
 * which this class never augments with the password or connection string (those were never
 * passed to this class as values to include in a message; they live only inside the
 * {@link LettuceConnectionFactory} already configured before this class ever sees it).
 */
public class RevocationChecker {

    private static final Logger log = LoggerFactory.getLogger(RevocationChecker.class);

    private static final String REVOKED_KEY_PREFIX = "revoked:";
    private static final String EPOCH_KEY = "revocation-epoch";
    private static final String REDIS_WRITE_FAILED_AFTER_DB_COMMIT_COUNTER =
            "giveaway.revocation.redis.write.failed.after.db.commit";

    private final DataSource dataSource;
    private final LettuceConnectionFactory connectionFactory;
    private final Clock clock;
    private final Duration epochWindow;
    private final Duration epochTtl;
    private final MeterRegistry meterRegistry;

    public RevocationChecker(DataSource dataSource, LettuceConnectionFactory connectionFactory,
            Clock clock, Duration epochWindow, Duration epochTtl) {
        this(dataSource, connectionFactory, clock, epochWindow, epochTtl, new SimpleMeterRegistry());
    }

    public RevocationChecker(DataSource dataSource, LettuceConnectionFactory connectionFactory,
            Clock clock, Duration epochWindow, Duration epochTtl, MeterRegistry meterRegistry) {
        if (epochTtl.compareTo(epochWindow.multipliedBy(2)) < 0) {
            throw new IllegalArgumentException(
                    "epochTtl (" + epochTtl + ") must be at least twice epochWindow (" + epochWindow
                            + ") -- see class Javadoc for why a shorter epoch TTL risks revoking live sessions");
        }
        this.dataSource = dataSource;
        this.connectionFactory = connectionFactory;
        this.clock = clock;
        this.epochWindow = epochWindow;
        this.epochTtl = epochTtl;
        this.meterRegistry = meterRegistry;
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

    /**
     * Reads the current revocation-epoch marker, initializing it to now if absent (the absence
     * itself is the signal that Redis just lost all its prior data -- see class Javadoc), and
     * refreshes its TTL on every successful read -- a sliding window, never a plain fixed expiry.
     * {@code SET ... NX EX} is used for initialization so the write and its TTL land atomically
     * (no window where the key exists without one); a race between concurrent callers all
     * discovering the absence at once still converges on a single value, since only one {@code
     * NX} write can succeed and every caller re-reads afterward rather than trusting its own
     * candidate value blindly.
     */
    private Instant readOrInitEpoch(RedisConnection conn) {
        byte[] epochKey = EPOCH_KEY.getBytes(StandardCharsets.UTF_8);
        byte[] existing = conn.stringCommands().get(epochKey);
        if (existing == null) {
            byte[] candidate = String.valueOf(clock.instant().toEpochMilli()).getBytes(StandardCharsets.UTF_8);
            conn.stringCommands().set(epochKey, candidate,
                    Expiration.seconds(epochTtl.toSeconds()), RedisStringCommands.SetOption.ifAbsent());
            existing = conn.stringCommands().get(epochKey);
        }
        else {
            // Sliding refresh: this read alone extends the key's life, independent of whether
            // this call initialized it just now (which already set a fresh TTL above).
            conn.keyCommands().expire(epochKey, epochTtl);
        }
        return parseEpoch(existing);
    }

    private static Instant parseEpoch(byte[] value) {
        return Instant.ofEpochMilli(Long.parseLong(new String(value, StandardCharsets.UTF_8)));
    }

    private static byte[] revokedKey(UUID familyId) {
        return (REVOKED_KEY_PREFIX + familyId).getBytes(StandardCharsets.UTF_8);
    }
}
