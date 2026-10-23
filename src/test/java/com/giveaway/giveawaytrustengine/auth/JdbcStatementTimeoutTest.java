package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.TestImages;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chunk 4 review, item 2: every statement in {@link RefreshTokenService},
 * {@link CommunityManagerRepository}, and {@link RevocationChecker} must be bounded -- a
 * statement blocked on a row lock held by a second connection must fail within the bound, not
 * hang indefinitely, and the caller must fail cleanly (the existing {@code IllegalStateException}
 * wrapping, not an uncaught/hanging call).
 *
 * <p><b>Chosen mechanism: a connection-level {@code statement_timeout}, not
 * {@code PreparedStatement.setQueryTimeout}.</b> pgjdbc's {@code setQueryTimeout} cancels a
 * running statement by opening a SEPARATE connection and sending Postgres's own out-of-band
 * Cancel-Request packet, keyed to the specific backend process/secret the original statement is
 * running on. That mechanism is well-known to be unreliable through a transaction-mode
 * PgBouncer/Supavisor pooler (the backend a cancel targets may not even be the one still running
 * the original client's work by the time the cancel arrives). A session-level
 * {@code statement_timeout} sidesteps this entirely: Postgres itself aborts the statement and
 * raises {@code QueryCanceledException} (SQLState {@code 57014}) over the SAME connection,
 * with no out-of-band cancel connection involved at all -- this works identically whether a
 * pooler is in the path or not. Supabase's own docs confirm session-level {@code statement_timeout}
 * is supported through its session pooler (not the transaction-mode one) -- this project already
 * uses the session pooler (CLAUDE.md's "Postgres" + the existing single, long-lived
 * {@code DataSource} pattern this slice's classes all share), so this is the mechanism that
 * actually works for this project's real deployment target, not just in a Testcontainers test.
 *
 * <p>Set once per physical connection via the JDBC URL's {@code options=-c statement_timeout=...}
 * parameter (mirrored in {@code application.properties} for the real app) -- this bounds EVERY
 * statement issued on that connection, including both statements of a multi-statement transaction
 * (e.g. {@link RefreshTokenService}'s single-transaction consume-and-rotate), without needing a
 * {@code setQueryTimeout} call at every individual {@code PreparedStatement} call site across all
 * three classes (eight-plus call sites, each one a chance to forget).
 */
@Testcontainers
class JdbcStatementTimeoutTest {

    private static final int STATEMENT_TIMEOUT_MS = 2000;
    private static final Instant FIXED_NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
    private static final String SIGNING_KEY = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("jdbc_statement_timeout_test")
            .withUsername("test")
            .withPassword("test");

    @BeforeAll
    static void startAndMigrate() {
        POSTGRES.start();
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load()
                .migrate();
    }

    @AfterAll
    static void stop() {
        POSTGRES.stop();
    }

    /** Every connection from this DataSource carries the same statement_timeout the real app would set. */
    private DataSource timeoutBoundedDataSource() {
        return new DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                Connection conn = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                try (Statement st = conn.createStatement()) {
                    st.execute("SET statement_timeout = " + STATEMENT_TIMEOUT_MS);
                }
                return conn;
            }

            @Override
            public Connection getConnection(String username, String password) throws SQLException {
                return getConnection();
            }

            @Override
            public <T> T unwrap(Class<T> iface) {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean isWrapperFor(Class<?> iface) {
                return false;
            }

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
                throw new UnsupportedOperationException();
            }
        };
    }

    private Connection rawConnection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    // RefreshTokenService.atomicallyConsumeAndRotate's UPDATE must be bounded: a second
    // connection holding the row lock (an open, uncommitted transaction) must make this call
    // fail within the statement_timeout bound, cleanly (IllegalStateException), not hang.
    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS) // bounds the TEST itself so a mutation (timeout removed) fails fast, never hangs CI
    void refreshTokenServiceUpdateFailsWithinBoundWhenRowIsLocked() throws Exception {
        UUID cmId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        byte[] secret = new byte[32];
        new java.security.SecureRandom().nextBytes(secret);
        byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(secret);

        try (Connection setup = rawConnection();
                PreparedStatement ps = setup.prepareStatement(
                        "INSERT INTO community_manager (id, x_handle, created_at, x_user_id) VALUES (?,?,?,?)")) {
            ps.setObject(1, cmId);
            ps.setString(2, "lockholder");
            ps.setTimestamp(3, Timestamp.from(FIXED_NOW));
            ps.setString(4, "x-" + UUID.randomUUID());
            ps.executeUpdate();
        }
        try (Connection setup = rawConnection();
                PreparedStatement ps = setup.prepareStatement(
                        "INSERT INTO refresh_token (token_id, family_id, cm_id, used, expires_at, token_hash) "
                                + "VALUES (?,?,?,false,?,?)")) {
            ps.setObject(1, tokenId);
            ps.setObject(2, familyId);
            ps.setObject(3, cmId);
            ps.setTimestamp(4, Timestamp.from(FIXED_NOW.plus(Duration.ofDays(7))));
            ps.setBytes(5, hash);
            ps.executeUpdate();
        }

        // Second connection holds the row lock open, uncommitted, for well past the bound.
        Connection lockHolder = rawConnection();
        lockHolder.setAutoCommit(false);
        try (PreparedStatement ps = lockHolder.prepareStatement(
                "UPDATE refresh_token SET used = true WHERE token_id = ?")) {
            ps.setObject(1, tokenId);
            ps.executeUpdate();
        }

        try {
            String cookieValue = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(tokenId.toString().getBytes())
                    + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);

            RevocationChecker revocationChecker = new RevocationChecker(
                    timeoutBoundedDataSource(), null, CLOCK, Duration.ofMinutes(15));
            RefreshTokenService service = new RefreshTokenService(
                    timeoutBoundedDataSource(), CLOCK, revocationChecker, new JwtService(SIGNING_KEY, CLOCK));

            long start = System.nanoTime();
            org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> service.refresh(cookieValue));
            long elapsedMs = Duration.ofNanos(System.nanoTime() - start).toMillis();

            assertThat(elapsedMs)
                    .as("must fail within a small multiple of the %dms bound, never hang indefinitely",
                            STATEMENT_TIMEOUT_MS)
                    .isLessThan(STATEMENT_TIMEOUT_MS * 5L);
        } finally {
            lockHolder.rollback();
            lockHolder.close();
        }
    }

    // CommunityManagerRepository.upsertByXUserId's INSERT ... ON CONFLICT ... DO UPDATE must be
    // bounded: a second connection holding the conflicting row's lock must make this call fail
    // within the bound, cleanly, not hang.
    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    void communityManagerRepositoryUpsertFailsWithinBoundWhenRowIsLocked() throws Exception {
        String xUserId = "x-" + UUID.randomUUID();
        UUID cmId = UUID.randomUUID();
        try (Connection setup = rawConnection();
                PreparedStatement ps = setup.prepareStatement(
                        "INSERT INTO community_manager (id, x_handle, created_at, x_user_id) VALUES (?,?,?,?)")) {
            ps.setObject(1, cmId);
            ps.setString(2, "lockholder2");
            ps.setTimestamp(3, Timestamp.from(FIXED_NOW));
            ps.setString(4, xUserId);
            ps.executeUpdate();
        }

        Connection lockHolder = rawConnection();
        lockHolder.setAutoCommit(false);
        try (PreparedStatement ps = lockHolder.prepareStatement(
                "SELECT id FROM community_manager WHERE id = ? FOR UPDATE")) {
            ps.setObject(1, cmId);
            ps.executeQuery();
        }

        try {
            CommunityManagerRepository repo = new CommunityManagerRepository(timeoutBoundedDataSource(), CLOCK);

            long start = System.nanoTime();
            org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> repo.upsertByXUserId(xUserId, "new_handle"));
            long elapsedMs = Duration.ofNanos(System.nanoTime() - start).toMillis();

            assertThat(elapsedMs)
                    .as("must fail within a small multiple of the %dms bound, never hang indefinitely",
                            STATEMENT_TIMEOUT_MS)
                    .isLessThan(STATEMENT_TIMEOUT_MS * 5L);
        } finally {
            lockHolder.rollback();
            lockHolder.close();
        }
    }

    // RevocationChecker.revokeFamily's UPDATE (the DB-first half of the revocation ordering)
    // must be bounded: a second connection holding the row lock must make this call fail within
    // the bound, cleanly, not hang.
    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    void revocationCheckerRevokeFamilyFailsWithinBoundWhenRowIsLocked() throws Exception {
        UUID cmId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        try (Connection setup = rawConnection();
                PreparedStatement ps = setup.prepareStatement(
                        "INSERT INTO community_manager (id, x_handle, created_at, x_user_id) VALUES (?,?,?,?)")) {
            ps.setObject(1, cmId);
            ps.setString(2, "lockholder3");
            ps.setTimestamp(3, Timestamp.from(FIXED_NOW));
            ps.setString(4, "x-" + UUID.randomUUID());
            ps.executeUpdate();
        }
        try (Connection setup = rawConnection();
                PreparedStatement ps = setup.prepareStatement(
                        "INSERT INTO refresh_token (token_id, family_id, cm_id, used, expires_at, token_hash) "
                                + "VALUES (?,?,?,false,?,?)")) {
            ps.setObject(1, tokenId);
            ps.setObject(2, familyId);
            ps.setObject(3, cmId);
            ps.setTimestamp(4, Timestamp.from(FIXED_NOW.plus(Duration.ofDays(7))));
            ps.setBytes(5, new byte[32]);
            ps.executeUpdate();
        }

        Connection lockHolder = rawConnection();
        lockHolder.setAutoCommit(false);
        try (PreparedStatement ps = lockHolder.prepareStatement(
                "UPDATE refresh_token SET used = true WHERE token_id = ?")) {
            ps.setObject(1, tokenId);
            ps.executeUpdate();
        }

        try {
            RevocationChecker checker = new RevocationChecker(timeoutBoundedDataSource(), null, CLOCK, Duration.ofMinutes(15));

            long start = System.nanoTime();
            org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> checker.revokeFamily(familyId));
            long elapsedMs = Duration.ofNanos(System.nanoTime() - start).toMillis();

            assertThat(elapsedMs)
                    .as("must fail within a small multiple of the %dms bound, never hang indefinitely",
                            STATEMENT_TIMEOUT_MS)
                    .isLessThan(STATEMENT_TIMEOUT_MS * 5L);
        } finally {
            lockHolder.rollback();
            lockHolder.close();
        }
    }
}
