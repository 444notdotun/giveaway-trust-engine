package com.giveaway.giveawaytrustengine.auth;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Rotates refresh tokens and detects reuse. See docs/slices/03-auth.md, Section 2 (rotation)
 * and Section 4 (revocation) -- CRITICAL REVIEW scope.
 *
 * Refresh tokens are never JWTs: the cookie value is {@code base64url(tokenId) + "." +
 * base64url(secret)} -- a split identifier+secret, matching {@code token_id} (the row's primary
 * key) to a freshly generated, high-entropy secret whose SHA-256 hash is the only thing ever
 * stored (Section 2: "stored hashed, never raw" -- {@code secretMatches} never compares the raw
 * secret to anything persisted).
 *
 * <p><b>Single-use consumption and rotation happen in one database transaction</b>
 * ({@link #atomicallyConsumeAndRotate}), not two separate statements each auto-committing on
 * their own. This closes a real race beyond the atomic-UPDATE-with-WHERE-clause pattern alone
 * (the same pattern CLAUDE.md's {@code claimRoll()} quota claim already uses): without the
 * transaction, a losing thread's reuse-triggered {@code revokeFamily} call could run in the
 * window between the winning thread's "mark old token used" commit and its "insert new token"
 * commit, missing the brand-new rotated token entirely. Wrapping both statements in one
 * transaction means Postgres's row lock on the {@code UPDATE} blocks a concurrent thread's own
 * {@code UPDATE} attempt on the same row until this whole transaction -- update AND insert --
 * has committed, so by the time a losing thread re-checks, the new token already exists and is
 * caught by the family-wide revocation.
 *
 * <p>An unknown {@code token_id} and a wrong secret for a real {@code token_id} both throw the
 * same {@link ReuseDetectedException} as genuine reuse -- deliberately indistinguishable from
 * the outside, so a caller probing random token values learns nothing about which case actually
 * happened. The same discipline applies to whether a reuse-triggered family revocation's Redis
 * write succeeded or failed ({@link #revokeFamilySwallowingRedisFailure}): either way, the
 * caller sees the identical generic rejection.
 */
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private static final Duration REFRESH_TOKEN_LIFETIME = Duration.ofDays(7);
    private static final int SECRET_LENGTH_BYTES = 32;

    /**
     * The ONE message every {@link ReuseDetectedException} this class throws carries -- a
     * malformed cookie, an unknown token_id, a wrong secret, and genuine reuse are all
     * byte-identical from the outside (item 4). Never add a case-specific message here; a
     * second literal string would immediately reopen the distinguishability this exists to
     * close.
     */
    static final String GENERIC_REJECTION_MESSAGE = "refresh token invalid";

    /** Chunk 4 review, item 1: one counter, tagged by reason, for every auth failure path. */
    private static final String FAILURE_COUNTER_NAME = "giveaway.auth.failure";

    private final DataSource dataSource;
    private final Clock clock;
    private final RevocationChecker revocationChecker;
    private final JwtService jwtService;
    private final MeterRegistry meterRegistry;

    public RefreshTokenService(DataSource dataSource, Clock clock, RevocationChecker revocationChecker,
            JwtService jwtService) {
        this(dataSource, clock, revocationChecker, jwtService, new SimpleMeterRegistry());
    }

    public RefreshTokenService(DataSource dataSource, Clock clock, RevocationChecker revocationChecker,
            JwtService jwtService, MeterRegistry meterRegistry) {
        this.dataSource = dataSource;
        this.clock = clock;
        this.revocationChecker = revocationChecker;
        this.jwtService = jwtService;
        this.meterRegistry = meterRegistry;
    }

    public RefreshResult refresh(String cookieValue) {
        ParsedCookie parsed = parseCookie(cookieValue);

        // Read outside the atomic-consume transaction, purely to validate the secret and expiry
        // -- the single-use GUARANTEE comes entirely from the atomic UPDATE below (its WHERE
        // used = false re-validates against the committed truth at that moment), so a stale read
        // here is harmless, never load-bearing for correctness.
        RowSnapshot row = selectRow(parsed.tokenId());
        if (row == null || !secretMatches(parsed.secret(), row.tokenHash())) {
            // Bucketed under "malformed" for log/metric purposes (item 1) -- an unknown token_id
            // or a wrong secret for a real one is operationally the same "not a usable token"
            // case as a malformed cookie, distinct from a CONFIRMED single-use violation
            // (reuse-detected, below). The external response stays byte-identical either way
            // (item 4) -- only the operator-facing log/counter distinguishes them.
            recordFailure("malformed");
            throw new ReuseDetectedException(GENERIC_REJECTION_MESSAGE);
        }
        // Strict: accepted only while now is BEFORE expiresAt. now == expiresAt (not just
        // now.isAfter) is already expired -- the boundary instant itself does not get one more
        // accepted use.
        if (!clock.instant().isBefore(row.expiresAt())) {
            recordFailure("expired");
            throw new ExpiredRefreshTokenException("refresh token expired");
        }

        AtomicConsumeResult consumed = atomicallyConsumeAndRotate(parsed.tokenId(), row.familyId(), row.cmId());
        if (!consumed.won()) {
            revokeFamilySwallowingRedisFailure(row.familyId());
            recordFailure("reuse-detected");
            // Byte-identical to the "unknown token"/"wrong secret" rejection below -- never a
            // distinguishable message, so a caller can't tell reuse from an unknown token from
            // the response body alone (item 4).
            throw new ReuseDetectedException(GENERIC_REJECTION_MESSAGE);
        }

        String newAccessToken = jwtService.issueAccessToken(row.cmId(), row.familyId());
        String newCookieValue = buildCookieValue(consumed.newTokenId(), consumed.newSecret());
        return new RefreshResult(newAccessToken, newCookieValue, row.familyId());
    }

    /**
     * Issues the very first refresh token for a brand-new session (called once at login, before
     * any rotation has happened) -- no old token to consume, so no race to guard here.
     */
    public RefreshResult issueInitialRefreshToken(UUID cmId, UUID familyId) {
        UUID newTokenId = UUID.randomUUID();
        byte[] newSecret = randomSecret();
        insertNewToken(newTokenId, familyId, cmId, newSecret, clock.instant().plus(REFRESH_TOKEN_LIFETIME));

        String newAccessToken = jwtService.issueAccessToken(cmId, familyId);
        String newCookieValue = buildCookieValue(newTokenId, newSecret);
        return new RefreshResult(newAccessToken, newCookieValue, familyId);
    }

    private record AtomicConsumeResult(boolean won, UUID newTokenId, byte[] newSecret) {
    }

    private AtomicConsumeResult atomicallyConsumeAndRotate(UUID oldTokenId, UUID familyId, UUID cmId) {
        UUID newTokenId = UUID.randomUUID();
        byte[] newSecret = randomSecret();
        byte[] newHash = sha256(newSecret);
        Instant expiresAt = clock.instant().plus(REFRESH_TOKEN_LIFETIME);

        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(false);
            try {
                int updated;
                try (PreparedStatement ps = conn.prepareStatement(
                        "UPDATE refresh_token SET used = true WHERE token_id = ? AND used = false")) {
                    ps.setObject(1, oldTokenId);
                    updated = ps.executeUpdate();
                }
                if (updated == 0) {
                    conn.rollback();
                    return new AtomicConsumeResult(false, null, null);
                }

                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO refresh_token (token_id, family_id, cm_id, used, expires_at, token_hash) "
                                + "VALUES (?,?,?,false,?,?)")) {
                    ps.setObject(1, newTokenId);
                    ps.setObject(2, familyId);
                    ps.setObject(3, cmId);
                    ps.setTimestamp(4, Timestamp.from(expiresAt));
                    ps.setBytes(5, newHash);
                    ps.executeUpdate();
                }
                conn.commit();
                return new AtomicConsumeResult(true, newTokenId, newSecret);
            }
            catch (SQLException e) {
                conn.rollback();
                recordFailure("db-unavailable");
                throw new IllegalStateException("failed to rotate refresh token", e);
            }
        }
        catch (SQLException e) {
            recordFailure("db-unavailable");
            throw new IllegalStateException("failed to rotate refresh token", e);
        }
    }

    private void insertNewToken(UUID tokenId, UUID familyId, UUID cmId, byte[] secret, Instant expiresAt) {
        try (Connection conn = dataSource.getConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO refresh_token (token_id, family_id, cm_id, used, expires_at, token_hash) "
                                + "VALUES (?,?,?,false,?,?)")) {
            ps.setObject(1, tokenId);
            ps.setObject(2, familyId);
            ps.setObject(3, cmId);
            ps.setTimestamp(4, Timestamp.from(expiresAt));
            ps.setBytes(5, sha256(secret));
            ps.executeUpdate();
        }
        catch (SQLException e) {
            recordFailure("db-unavailable");
            throw new IllegalStateException("failed to issue refresh token", e);
        }
    }

    /**
     * On reuse, the DB-side revocation (every token in the family marked {@code used = true})
     * has already committed inside {@link RevocationChecker#revokeFamily} by the time it could
     * possibly throw -- only the downstream Redis write can fail. Swallowed here (logged, not
     * rethrown) so {@link #refresh(String)} always throws the identical {@link ReuseDetectedException}
     * regardless of whether that Redis write succeeded: which outcome happened must never be
     * observable from the response.
     */
    private void revokeFamilySwallowingRedisFailure(UUID familyId) {
        try {
            revocationChecker.revokeFamily(familyId);
        }
        catch (RuntimeException revocationFailure) {
            log.warn("family revocation on reuse detection did not fully complete: familyId={}", familyId);
        }
    }

    private RowSnapshot selectRow(UUID tokenId) {
        try (Connection conn = dataSource.getConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "SELECT family_id, cm_id, expires_at, token_hash FROM refresh_token WHERE token_id = ?")) {
            ps.setObject(1, tokenId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                return new RowSnapshot(
                        (UUID) rs.getObject("family_id"),
                        (UUID) rs.getObject("cm_id"),
                        rs.getTimestamp("expires_at").toInstant(),
                        rs.getBytes("token_hash"));
            }
        }
        catch (SQLException e) {
            recordFailure("db-unavailable");
            throw new IllegalStateException("failed to look up refresh token", e);
        }
    }

    private record RowSnapshot(UUID familyId, UUID cmId, Instant expiresAt, byte[] tokenHash) {
    }

    private record ParsedCookie(UUID tokenId, byte[] secret) {
    }

    private static final int MAX_COOKIE_LENGTH = 256;

    /**
     * Length/presence is checked BEFORE any decoding is even attempted -- {@code null}, empty,
     * and oversized (over {@value #MAX_COOKIE_LENGTH} characters) values are exactly the kind of
     * input a decoder could either throw an unexpected, less-generic exception for ({@code
     * NullPointerException} on {@code null}) or spend real work on (an attacker-sized string).
     * Checked first, rejected the same generic way as every other malformed case.
     */
    private ParsedCookie parseCookie(String cookieValue) {
        if (cookieValue == null || cookieValue.isEmpty() || cookieValue.length() > MAX_COOKIE_LENGTH) {
            recordFailure("malformed");
            throw new ReuseDetectedException(GENERIC_REJECTION_MESSAGE);
        }
        int dot = cookieValue.indexOf('.');
        if (dot < 0) {
            recordFailure("malformed");
            throw new ReuseDetectedException(GENERIC_REJECTION_MESSAGE);
        }
        UUID tokenId;
        try {
            String tokenIdString = new String(
                    Base64.getUrlDecoder().decode(cookieValue.substring(0, dot)), StandardCharsets.UTF_8);
            tokenId = UUID.fromString(tokenIdString);
        }
        catch (RuntimeException malformed) {
            recordFailure("malformed");
            throw new ReuseDetectedException(GENERIC_REJECTION_MESSAGE);
        }
        byte[] secret;
        try {
            secret = Base64.getUrlDecoder().decode(cookieValue.substring(dot + 1));
        }
        catch (IllegalArgumentException malformed) {
            recordFailure("malformed");
            throw new ReuseDetectedException(GENERIC_REJECTION_MESSAGE);
        }
        return new ParsedCookie(tokenId, secret);
    }

    /** {@code reason} is always a fixed, short category -- never the cookie, secret, or token value. */
    private void recordFailure(String reason) {
        log.warn("refresh rejected: reason={}", reason);
        meterRegistry.counter(FAILURE_COUNTER_NAME, "reason", reason).increment();
    }

    private static String buildCookieValue(UUID tokenId, byte[] secret) {
        String tokenIdPart = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tokenId.toString().getBytes(StandardCharsets.UTF_8));
        String secretPart = Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
        return tokenIdPart + "." + secretPart;
    }

    /** Constant-time comparison -- never a timing side-channel on the hash check itself. */
    private static boolean secretMatches(byte[] secret, byte[] storedHash) {
        return MessageDigest.isEqual(sha256(secret), storedHash);
    }

    private static byte[] randomSecret() {
        byte[] secret = new byte[SECRET_LENGTH_BYTES];
        new SecureRandom().nextBytes(secret);
        return secret;
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 must always be available", impossible);
        }
    }
}
