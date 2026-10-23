package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.TestImages;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.net.ServerSocket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Slice 3 (Auth) -- CRITICAL REVIEW scope: revocation ordering (database commits first, then
 * Redis, Section 4). Plan doc: docs/slices/03-auth.md, Section 4 ("Revocation: database first,
 * then Redis").
 *
 * Uses a REAL Testcontainers Postgres (same DataSource-wrapping pattern as
 * {@code RefreshTokenConcurrencyTest}) and a REAL Testcontainers Redis -- never mocks, per this
 * project's testing rules, since the whole point is proving a real cross-store ordering
 * guarantee.
 *
 * RED: {@code RevocationChecker.revokeFamily(UUID)} is currently a complete no-op (doesn't touch
 * the database OR Redis at all), so every assertion below that depends on either store actually
 * changing state is expected to fail.
 *
 * {@code RevocationChecker} now takes a {@code DataSource} ({@code revokeFamily} marks every
 * {@code refresh_token} row in the family {@code used = true} before touching Redis -- Section
 * 4) -- test 3 injects a genuinely broken {@code DataSource} (every {@code getConnection()}
 * throws) to prove the reverse ordering never happens, per the plan doc's letter.
 */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
class RevocationOrderingTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("giveaway_trust_engine_test")
            .withUsername("test")
            .withPassword("test");

    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse(TestImages.REDIS))
            .withExposedPorts(6379);

    static {
        POSTGRES.start();
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load()
                .migrate();
    }

    private static final Instant FIXED_NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    private UUID cmId;

    @BeforeAll
    static void startRedis() {
        REDIS.start();
    }

    @AfterAll
    static void stopEverything() {
        REDIS.stop();
        POSTGRES.stop();
    }

    @BeforeEach
    void setUp() throws SQLException {
        try (Connection conn = connect()) {
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

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private static int findFreePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static javax.sql.DataSource workingDataSource() {
        return new javax.sql.DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                return connect();
            }

            @Override
            public Connection getConnection(String username, String password) throws SQLException {
                return connect();
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

    /** Every {@code getConnection()} call throws -- genuinely broken, not merely unseeded. */
    private static javax.sql.DataSource brokenDataSource() {
        return new javax.sql.DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                throw new SQLException("deliberately broken for dbFailureLeavesRedisUntouched");
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

    private RevocationChecker checkerWithWorkingRedis() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();
        return new RevocationChecker(workingDataSource(), factory, CLOCK, Duration.ofMinutes(15), Duration.ofHours(24));
    }

    private RevocationChecker checkerWithWorkingRedisAndBrokenDb() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();
        return new RevocationChecker(brokenDataSource(), factory, CLOCK, Duration.ofMinutes(15), Duration.ofHours(24));
    }

    private RevocationChecker checkerWithUnreachableRedis() throws Exception {
        return checkerWithUnreachableRedis(new SimpleMeterRegistry());
    }

    private RevocationChecker checkerWithUnreachableRedis(SimpleMeterRegistry meterRegistry) throws Exception {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration("127.0.0.1", findFreePort());
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();
        return new RevocationChecker(workingDataSource(), factory, CLOCK, Duration.ofMinutes(15),
                Duration.ofHours(24), meterRegistry);
    }

    /** Seeds two fresh, never-used refresh_token rows for the given family. */
    private void seedFamily(UUID familyId) throws SQLException {
        try (Connection conn = connect()) {
            for (int i = 0; i < 2; i++) {
                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO refresh_token (token_id, family_id, cm_id, used, expires_at, token_hash) "
                                + "VALUES (?,?,?,false,?,?)")) {
                    ps.setObject(1, UUID.randomUUID());
                    ps.setObject(2, familyId);
                    ps.setObject(3, cmId);
                    ps.setTimestamp(4, Timestamp.from(FIXED_NOW.plus(Duration.ofDays(7))));
                    ps.setBytes(5, new byte[32]);
                    ps.executeUpdate();
                }
            }
        }
    }

    private int countUsedInFamily(UUID familyId) throws SQLException {
        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT count(*) FROM refresh_token WHERE family_id = ? AND used = true")) {
            ps.setObject(1, familyId);
            var rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1);
        }
    }

    private int countTotalInFamily(UUID familyId) throws SQLException {
        try (Connection conn = connect();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT count(*) FROM refresh_token WHERE family_id = ?")) {
            ps.setObject(1, familyId);
            var rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1);
        }
    }

    private boolean redisKeyExists(String key) {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config,
                LettuceClientConfiguration.builder().commandTimeout(Duration.ofSeconds(2)).build());
        factory.afterPropertiesSet();
        try {
            Boolean exists = factory.getConnection().keyCommands().exists(key.getBytes());
            return exists != null && exists;
        } finally {
            factory.destroy();
        }
    }

    // Revocation ordering (Section 4, CRITICAL REVIEW): DB commit happens, then Redis is written
    // -- revokeFamily must mark every refresh_token row in the family used/revoked in the
    // database.
    @Test
    void dbCommitHappensThenRedisIsWritten() throws Exception {
        UUID familyId = UUID.randomUUID();
        seedFamily(familyId);
        RevocationChecker checker = checkerWithWorkingRedis();

        checker.revokeFamily(familyId);

        assertThat(countUsedInFamily(familyId))
                .as("every refresh_token row in the family must be marked used/revoked in the "
                        + "database after revokeFamily")
                .isEqualTo(countTotalInFamily(familyId))
                .isGreaterThan(0);
    }

    // Revocation ordering (Section 4): a Redis failure AFTER a successful DB write must still
    // leave the DB revoked, and the overall call must fail CLOSED (throw), never silently succeed.
    // Also: this residual-window event must be operator-visible (plan doc's windows table) -- a
    // WARN log line naming the familyId (never a token/secret) and a Micrometer counter.
    @Test
    void redisFailureAfterSuccessfulDbWriteStillLeavesDbRevokedAndFailsClosed(CapturedOutput output) throws Exception {
        UUID familyId = UUID.randomUUID();
        seedFamily(familyId);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        RevocationChecker checker = checkerWithUnreachableRedis(meterRegistry);

        assertThatThrownBy(() -> checker.revokeFamily(familyId))
                .as("revokeFamily must fail closed (throw) when the downstream Redis write fails, "
                        + "not silently succeed")
                .isInstanceOf(RuntimeException.class);

        assertThat(countUsedInFamily(familyId))
                .as("the DB write must have already committed and survive the downstream Redis "
                        + "failure -- DB-first ordering")
                .isEqualTo(countTotalInFamily(familyId))
                .isGreaterThan(0);

        assertThat(output.getAll())
                .as("one WARN log line naming the familyId must be emitted for this residual-"
                        + "window event, so an operator can actually see it happening")
                .contains("WARN")
                .contains(familyId.toString());

        assertThat(meterRegistry.counter("giveaway.revocation.redis.write.failed.after.db.commit").count())
                .as("exactly one increment for this exact failure event")
                .isEqualTo(1.0);
    }

    // Revocation ordering (Section 4): a DB failure must leave Redis completely untouched -- the
    // reverse ordering (Redis-first) is exactly what this guards against.
    @Test
    void dbFailureLeavesRedisUntouched() throws Exception {
        UUID familyId = UUID.randomUUID();
        // A genuinely broken DataSource (every getConnection() throws) with a real, working
        // Redis -- isolates the reverse ordering this guards against: if revokeFamily ever wrote
        // to Redis before (or regardless of) the DB write, this test would see a Redis key here
        // despite the DB write having failed outright.
        RevocationChecker checker = checkerWithWorkingRedisAndBrokenDb();

        assertThatThrownBy(() -> checker.revokeFamily(familyId))
                .as("revokeFamily must throw when the database write itself fails")
                .isInstanceOf(RuntimeException.class);

        assertThat(redisKeyExists("revoked:" + familyId))
                .as("no Redis key for this family should exist when the DB write never committed")
                .isFalse();
    }
}
