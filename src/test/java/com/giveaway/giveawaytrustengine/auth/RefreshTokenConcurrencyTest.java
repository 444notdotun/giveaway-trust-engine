package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.TestImages;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Slice 3 (Auth) -- CRITICAL REVIEW scope: reuse detection and revocation ordering.
 * Plan doc: docs/slices/03-auth.md, Section 2 (rotation), Section 4 (revocation), Section 5
 * (failure tests 1, 2, 3) + happy-path refresh (Tests summary).
 *
 * Concurrency tests use REAL THREADS against a REAL Testcontainers Postgres, never mocks
 * (per this project's testing rules) -- the whole point of test 1 is proving the atomic
 * conditional UPDATE actually serializes the race, which a mock can never demonstrate.
 *
 * RED: {@code RefreshTokenService} and {@code ReuseDetectedException} do not exist yet.
 */
@Testcontainers
class RefreshTokenConcurrencyTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("giveaway_trust_engine_test")
            .withUsername("test")
            .withPassword("test");

    static {
        POSTGRES.start();
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load()
                .migrate();
    }

    private static final String SIGNING_KEY = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
    private static final Instant FIXED_NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    private DataSource dataSource;
    private UUID cmId;

    @BeforeAll
    static void noop() {
        // container + migration already started/applied above.
    }

    @AfterAll
    static void stopContainer() {
        POSTGRES.stop();
    }

    @BeforeEach
    void setUp() throws SQLException {
        dataSource = simpleDataSource();
        try (Connection conn = dataSource.getConnection()) {
            cmId = UUID.randomUUID();
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO community_manager (id, x_handle, x_user_id, created_at) VALUES (?,?,?,?)")) {
                ps.setObject(1, cmId);
                ps.setString(2, "@cm_" + cmId);
                ps.setString(3, "x-user-" + cmId);
                ps.setTimestamp(4, Timestamp.from(FIXED_NOW));
                ps.executeUpdate();
            }
        }
    }

    private DataSource simpleDataSource() {
        return new DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                return DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
            }

            @Override
            public Connection getConnection(String username, String password) throws SQLException {
                return getConnection();
            }

            // Remaining DataSource methods are irrelevant to this RED-step test.
            @Override
            public java.io.PrintWriter getLogWriter() {
                return null;
            }

            @Override
            public void setLogWriter(java.io.PrintWriter out) {
            }

            @Override
            public void setLoginTimeout(int seconds) {
            }

            @Override
            public int getLoginTimeout() {
                return 0;
            }

            @Override
            public java.util.logging.Logger getParentLogger() {
                return null;
            }

            @Override
            public <T> T unwrap(Class<T> iface) {
                return null;
            }

            @Override
            public boolean isWrapperFor(Class<?> iface) {
                return false;
            }
        };
    }

    /** Inserts a fresh single-use refresh token row and returns the cookie value for it. */
    private String insertFreshToken(UUID tokenId, UUID familyId, boolean used) throws SQLException {
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        byte[] hash;
        try {
            hash = MessageDigest.getInstance("SHA-256").digest(secret);
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "INSERT INTO refresh_token (token_id, family_id, cm_id, used, expires_at, token_hash) "
                             + "VALUES (?,?,?,?,?,?)")) {
            ps.setObject(1, tokenId);
            ps.setObject(2, familyId);
            ps.setObject(3, cmId);
            ps.setBoolean(4, used);
            ps.setTimestamp(5, Timestamp.from(FIXED_NOW.plus(Duration.ofDays(7))));
            ps.setBytes(6, hash);
            ps.executeUpdate();
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenId.toString().getBytes())
                + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
    }

    private int countUsedInFamily(UUID familyId) throws SQLException {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT count(*) FROM refresh_token WHERE family_id = ? AND used = true")) {
            ps.setObject(1, familyId);
            var rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1);
        }
    }

    private int countTotalInFamily(UUID familyId) throws SQLException {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT count(*) FROM refresh_token WHERE family_id = ?")) {
            ps.setObject(1, familyId);
            var rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1);
        }
    }

    // Failure test 1 (Section 5.1): two concurrent refreshes with the IDENTICAL tokenId/secret --
    // exactly one wins (new rotated pair), the other triggers reuse handling, and afterward
    // every token in the family has used = true in the database.
    @Test
    void concurrentRefreshesWithSameTokenExactlyOneWins() throws Exception {
        UUID familyId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        String cookieValue = insertFreshToken(tokenId, familyId, false);

        RevocationChecker revocationChecker = new RevocationChecker(simpleDataSource(), null, CLOCK, Duration.ofMinutes(15), Duration.ofHours(24));
        RefreshTokenService service = new RefreshTokenService(dataSource, CLOCK, revocationChecker, new JwtService(SIGNING_KEY, CLOCK));

        CountDownLatch startLatch = new CountDownLatch(2);
        CountDownLatch doneLatch = new CountDownLatch(2);
        AtomicInteger successCount = new AtomicInteger();
        AtomicInteger reuseCount = new AtomicInteger();
        AtomicReference<Throwable> unexpected = new AtomicReference<>();

        Runnable attempt = () -> {
            try {
                startLatch.countDown();
                startLatch.await();
                service.refresh(cookieValue);
                successCount.incrementAndGet();
            } catch (ReuseDetectedException reuse) {
                reuseCount.incrementAndGet();
            } catch (Throwable t) {
                unexpected.set(t);
            } finally {
                doneLatch.countDown();
            }
        };

        Thread t1 = new Thread(attempt);
        Thread t2 = new Thread(attempt);
        t1.start();
        t2.start();
        doneLatch.await();

        assertThat(unexpected.get()).as("no unexpected exception from either thread").isNull();
        assertThat(successCount.get()).as("exactly one thread rotates successfully").isEqualTo(1);
        assertThat(reuseCount.get()).as("exactly one thread sees reuse detected").isEqualTo(1);
        assertThat(countTotalInFamily(familyId))
                .as("every token in the family (the original plus the one rotation) has used = true")
                .isEqualTo(countUsedInFamily(familyId));
    }

    // Failure test 2 (Section 5.2): reuse of a rotated token revokes the whole family -- refresh
    // once (A -> B, A now used), then present A again; every token in the family (including B,
    // never used or expired) becomes used = true, and a subsequent refresh using B also fails.
    @Test
    void reuseOfRotatedTokenRevokesWholeFamily() throws Exception {
        UUID familyId = UUID.randomUUID();
        UUID tokenAId = UUID.randomUUID();
        String tokenACookie = insertFreshToken(tokenAId, familyId, false);

        RevocationChecker revocationChecker = new RevocationChecker(simpleDataSource(), null, CLOCK, Duration.ofMinutes(15), Duration.ofHours(24));
        RefreshTokenService service = new RefreshTokenService(dataSource, CLOCK, revocationChecker, new JwtService(SIGNING_KEY, CLOCK));

        RefreshResult rotated = service.refresh(tokenACookie); // A -> B
        assertThat(rotated).isNotNull();

        assertThat(countTotalInFamily(familyId)).isEqualTo(2); // A (used) + B (not used)
        assertThat(countUsedInFamily(familyId)).isEqualTo(1);

        // Present A again -- reuse.
        final String rotatedTokenBCookie = rotated.newRefreshCookieValue();
        org.junit.jupiter.api.Assertions.assertThrows(ReuseDetectedException.class,
                () -> service.refresh(tokenACookie));

        assertThat(countUsedInFamily(familyId))
                .as("every token in the family, including B which was never used by anyone, "
                        + "must now be used = true")
                .isEqualTo(countTotalInFamily(familyId));

        // A subsequent refresh using B (the never-actually-compromised, newer token) must also fail.
        org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
                () -> service.refresh(rotatedTokenBCookie));
    }

    // Failure test 3 (Section 5.3): after family revocation, ANY further refresh attempt
    // against ANY token in that family fails -- not just the originally-reused one.
    @Test
    void revokedTokenIsRejectedForAnyTokenInFamily() throws Exception {
        UUID familyId = UUID.randomUUID();
        UUID tokenAId = UUID.randomUUID();
        UUID tokenCId = UUID.randomUUID();
        String tokenACookie = insertFreshToken(tokenAId, familyId, false);
        String tokenCCookie = insertFreshToken(tokenCId, familyId, false); // sibling, never touched

        RevocationChecker revocationChecker = new RevocationChecker(simpleDataSource(), null, CLOCK, Duration.ofMinutes(15), Duration.ofHours(24));
        RefreshTokenService service = new RefreshTokenService(dataSource, CLOCK, revocationChecker, new JwtService(SIGNING_KEY, CLOCK));

        service.refresh(tokenACookie); // rotates A -> new token, family now partially used
        org.junit.jupiter.api.Assertions.assertThrows(ReuseDetectedException.class,
                () -> service.refresh(tokenACookie)); // reuse -> revokes whole family

        // tokenC was never used by anyone, but its family is now revoked -- must still fail.
        org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
                () -> service.refresh(tokenCCookie));
    }

    // Happy-path refresh (Tests summary): valid token -> rotated pair, old token used = true,
    // new token usable.
    @Test
    void happyPathRefreshRotatesPairAndMarksOldTokenUsed() throws Exception {
        UUID familyId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        String cookieValue = insertFreshToken(tokenId, familyId, false);

        RevocationChecker revocationChecker = new RevocationChecker(simpleDataSource(), null, CLOCK, Duration.ofMinutes(15), Duration.ofHours(24));
        RefreshTokenService service = new RefreshTokenService(dataSource, CLOCK, revocationChecker, new JwtService(SIGNING_KEY, CLOCK));

        RefreshResult result = service.refresh(cookieValue);

        assertThat(result.newAccessToken()).isNotBlank();
        assertThat(result.newRefreshCookieValue()).isNotBlank().isNotEqualTo(cookieValue);
        assertThat(result.familyId()).isEqualTo(familyId);

        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT used FROM refresh_token WHERE token_id = ?")) {
            ps.setObject(1, tokenId);
            var rs = ps.executeQuery();
            rs.next();
            assertThat(rs.getBoolean(1)).as("the old token must now be used = true").isTrue();
        }

        // New token is itself usable for a further refresh.
        RefreshResult second = service.refresh(result.newRefreshCookieValue());
        assertThat(second.familyId()).isEqualTo(familyId);
    }

    // Refresh tokens must be stored hashed -- the raw secret must never appear as the literal
    // stored bytes in refresh_token.token_hash.
    @Test
    void refreshTokensAreStoredHashedNeverRawInTokenHashColumn() throws Exception {
        UUID familyId = UUID.randomUUID();

        RevocationChecker revocationChecker = new RevocationChecker(simpleDataSource(), null, CLOCK, Duration.ofMinutes(15), Duration.ofHours(24));
        RefreshTokenService service = new RefreshTokenService(dataSource, CLOCK, revocationChecker, new JwtService(SIGNING_KEY, CLOCK));

        RefreshResult result = service.issueInitialRefreshToken(cmId, familyId);

        assertThat(result).isNotNull();
        String rawCookieValue = result.newRefreshCookieValue();
        String rawSecretHalfBase64 = rawCookieValue.substring(rawCookieValue.indexOf('.') + 1);
        // The cookie's secret half is base64url-ENCODED -- decode it to get the actual raw
        // secret bytes. Comparing against the base64 STRING's own UTF-8 bytes (a prior version
        // of this test's bug) can never catch a mutation that stores the raw secret directly:
        // the encoded string's bytes and the real raw secret bytes have different lengths and
        // values regardless of whether real hashing happens, so that comparison always passes
        // vacuously. Confirmed directly: a mutation storing the raw secret via
        // `ps.setBytes(5, secret)` instead of `ps.setBytes(5, sha256(secret))` passed this test
        // unmodified -- this decode is the fix.
        byte[] rawSecretBytes = java.util.Base64.getUrlDecoder().decode(rawSecretHalfBase64);

        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT token_hash FROM refresh_token WHERE family_id = ?")) {
            ps.setObject(1, familyId);
            var rs = ps.executeQuery();
            assertThat(rs.next()).as("a refresh_token row must have been inserted").isTrue();
            byte[] storedHash = rs.getBytes("token_hash");
            assertThat(storedHash)
                    .as("the raw secret must never be stored literally as token_hash")
                    .isNotEqualTo(rawSecretBytes);
        }
    }

    // Failure test 3 variant (Section 5, expired refresh token): a refresh token whose
    // expires_at is in the past (relative to the injected Clock) must be rejected specifically
    // with ExpiredRefreshTokenException, not just "any exception".
    @Test
    void expiredRefreshTokenIsRejectedWithSpecificException() throws Exception {
        UUID familyId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        String cookieValue = insertExpiredToken(tokenId, familyId);

        RevocationChecker revocationChecker = new RevocationChecker(simpleDataSource(), null, CLOCK, Duration.ofMinutes(15), Duration.ofHours(24));
        RefreshTokenService service = new RefreshTokenService(dataSource, CLOCK, revocationChecker, new JwtService(SIGNING_KEY, CLOCK));

        org.junit.jupiter.api.Assertions.assertThrows(ExpiredRefreshTokenException.class,
                () -> service.refresh(cookieValue));
    }

    /** Inserts a refresh_token row whose expires_at is already in the past relative to CLOCK. */
    private String insertExpiredToken(UUID tokenId, UUID familyId) throws SQLException {
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        byte[] hash;
        try {
            hash = MessageDigest.getInstance("SHA-256").digest(secret);
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "INSERT INTO refresh_token (token_id, family_id, cm_id, used, expires_at, token_hash) "
                             + "VALUES (?,?,?,?,?,?)")) {
            ps.setObject(1, tokenId);
            ps.setObject(2, familyId);
            ps.setObject(3, cmId);
            ps.setBoolean(4, false);
            ps.setTimestamp(5, Timestamp.from(FIXED_NOW.minus(Duration.ofDays(1)))); // already expired
            ps.setBytes(6, hash);
            ps.executeUpdate();
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenId.toString().getBytes())
                + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
    }
}
