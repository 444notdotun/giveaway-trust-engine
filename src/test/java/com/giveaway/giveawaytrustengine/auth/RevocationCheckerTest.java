package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.TestImages;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import javax.sql.DataSource;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Slice 3 (Auth) -- CRITICAL REVIEW scope (revocation ordering).
 * Plan doc: docs/slices/03-auth.md, Section 1 (TLS/auth on Redis), Section 4
 * (RevocationChecker / RevocationCheckUnavailableException), Section 4a (revocation-epoch),
 * Section 5 (failure tests 7, 10, 11, 12, 21).
 *
 * RED: {@code RevocationChecker} and {@code RevocationCheckUnavailableException} do not exist
 * yet.
 *
 * The TLS+auth Redis container mirrors Upstash's mandatory posture (plan doc Section 1) rather
 * than a trivial unauthenticated local instance -- a self-signed cert is generated once per test
 * class and the container is started with --tls-port/--requirepass exactly as the plan specifies.
 */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
class RevocationCheckerTest {

    private static final String REDIS_PASSWORD = "s3cr3t-upstash-style-token";
    private static final Instant FIXED_NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    static GenericContainer<?> TLS_REDIS;
    static Path certDir;

    // revokeFamily now writes to refresh_token (Section 4, DB-first) -- a real Postgres is
    // needed here too, same pattern as RevocationOrderingTest. This test class doesn't care
    // about specific row counts (no rows are seeded for the UUIDs it uses), only that the write
    // succeeds against a real, migrated schema.
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("revocation_checker_test")
            .withUsername("test")
            .withPassword("test");

    static {
        POSTGRES.start();
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load()
                .migrate();
    }

    private static DataSource postgresDataSource() {
        return new DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
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

    @BeforeAll
    static void startTlsRedis() throws Exception {
        certDir = Files.createTempDirectory("revocation-checker-tls");
        generateSelfSignedCertWithRedisHelper(certDir);

        // Copying the whole directory (withCopyFileToContainer(MountableFile.forHostPath(certDir), ...))
        // preserves the host's file permissions -- openssl writes key files with a restrictive
        // umask (often 600, owned by the host UID), which the container's redis user then can't
        // read. Copying each file individually with an explicit, permissive mode sidesteps that;
        // these are throwaway test-only certs, so world-readable is not a real exposure.
        TLS_REDIS = new GenericContainer<>(DockerImageName.parse(TestImages.REDIS))
                .withExposedPorts(6380)
                .withCopyFileToContainer(MountableFile.forHostPath(certDir.resolve("ca.crt"), 0644), "/tls/ca.crt")
                .withCopyFileToContainer(MountableFile.forHostPath(certDir.resolve("redis.crt"), 0644), "/tls/redis.crt")
                .withCopyFileToContainer(MountableFile.forHostPath(certDir.resolve("redis.key"), 0644), "/tls/redis.key")
                .withCommand("redis-server",
                        "--tls-port", "6380",
                        "--port", "0",
                        "--tls-cert-file", "/tls/redis.crt",
                        "--tls-key-file", "/tls/redis.key",
                        "--tls-ca-cert-file", "/tls/ca.crt",
                        "--tls-auth-clients", "no",
                        "--requirepass", REDIS_PASSWORD);
        TLS_REDIS.start();
    }

    /**
     * {@code revocation-epoch} is a single GLOBAL key, shared across every test in this class
     * (unlike {@code revoked:{familyId}}, which each test already isolates via a fresh random
     * UUID). Without a reset, one test's manual TTL manipulation (e.g. {@code rawSetTtl}, used to
     * simulate time passing) or epoch initialization can leak into a LATER test's observations,
     * silently making it pass or fail for the wrong reason depending on execution order --
     * caught directly: a full-class mutation run showed {@code epochKeyHasATtlAfterInit} passing
     * under a mutation that removed all TTL-setting, only because an unrelated, earlier-run
     * test's leftover manual TTL was still on the key. Flushing before every test removes that
     * cross-test dependency entirely.
     */
    @BeforeEach
    void resetRedisState() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
                TLS_REDIS.getHost(), TLS_REDIS.getMappedPort(6380));
        config.setPassword(REDIS_PASSWORD);
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .useSsl().disablePeerVerification().and()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();
        try {
            factory.getConnection().serverCommands().flushAll();
        } finally {
            factory.destroy();
        }
    }

    @AfterAll
    static void stopTlsRedis() {
        if (TLS_REDIS != null) {
            TLS_REDIS.stop();
        }
        POSTGRES.stop();
    }

    /**
     * Generates a throwaway self-signed CA/cert/key using redis's own utility script shape,
     * via a plain `openssl` invocation (available in the test-running environment) -- avoids
     * depending on a library or on Redis's own (removed in newer images) utils/gen-test-certs.sh.
     */
    private static void generateSelfSignedCertWithRedisHelper(Path dir) throws IOException, InterruptedException {
        runOrFail(dir, "openssl", "genrsa", "-out", "ca.key", "2048");
        runOrFail(dir, "openssl", "req", "-x509", "-new", "-nodes", "-key", "ca.key",
                "-days", "2", "-subj", "/CN=Test-CA", "-out", "ca.crt");
        runOrFail(dir, "openssl", "genrsa", "-out", "redis.key", "2048");
        runOrFail(dir, "openssl", "req", "-new", "-key", "redis.key",
                "-subj", "/CN=localhost", "-out", "redis.csr");
        runOrFail(dir, "openssl", "x509", "-req", "-in", "redis.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "2", "-out", "redis.crt");
    }

    private static void runOrFail(Path dir, String... command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command).directory(dir.toFile())
                .redirectErrorStream(true).start();
        String out = new String(process.getInputStream().readAllBytes());
        int exit = process.waitFor();
        if (exit != 0) {
            throw new IllegalStateException("command failed (" + exit + "): " + String.join(" ", command)
                    + "\n" + out);
        }
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private RevocationChecker checkerWithPassword(String password) {
        return checkerWithPassword(password, Duration.ofMinutes(15), Duration.ofHours(24));
    }

    /**
     * {@code epochWindow} and {@code epochTtl} are both customizable (not just {@code epochTtl}
     * against a hardcoded 15-minute window) so TTL-refresh tests can use a tiny window+TTL pair
     * that still satisfies the constructor's own "epochTtl >= 2x epochWindow" validation, instead
     * of waiting out a real 15-minute access-token-lifetime-sized window in a unit test.
     */
    private RevocationChecker checkerWithPassword(String password, Duration epochWindow, Duration epochTtl) {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
                TLS_REDIS.getHost(), TLS_REDIS.getMappedPort(6380));
        config.setPassword(password);
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .useSsl().disablePeerVerification().and()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();
        return new RevocationChecker(postgresDataSource(), factory, CLOCK, epochWindow, epochTtl);
    }

    /** Reads the real TTL (seconds) of a key directly from Redis, bypassing RevocationChecker. */
    private long rawTtlSeconds(String key) {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
                TLS_REDIS.getHost(), TLS_REDIS.getMappedPort(6380));
        config.setPassword(REDIS_PASSWORD);
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .useSsl().disablePeerVerification().and()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();
        try {
            Long ttl = factory.getConnection().keyCommands().ttl(key.getBytes());
            return ttl == null ? -2 : ttl;
        } finally {
            factory.destroy();
        }
    }

    /** Sets a key's TTL directly via Redis, bypassing RevocationChecker (simulates time passing). */
    private void rawSetTtl(String key, long seconds) {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
                TLS_REDIS.getHost(), TLS_REDIS.getMappedPort(6380));
        config.setPassword(REDIS_PASSWORD);
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .useSsl().disablePeerVerification().and()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();
        try {
            factory.getConnection().keyCommands().expire(key.getBytes(), seconds);
        } finally {
            factory.destroy();
        }
    }

    // Section 4a, item 1(a): the revocation-epoch key must have a TTL, not live forever -- a
    // key with no TTL at all would violate CLAUDE.md's "every Redis key has a TTL" the same way
    // an un-TTL'd revoked:{familyId} key would.
    @Test
    void epochKeyHasATtlAfterInit() {
        RevocationChecker checker = checkerWithPassword(REDIS_PASSWORD, Duration.ofMinutes(15), Duration.ofHours(24));
        checker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60)); // triggers epoch init

        long ttl = rawTtlSeconds("revocation-epoch");
        assertThat(ttl)
                .as("revocation-epoch must have a real TTL after being initialized, not live forever")
                .isGreaterThan(0);
    }

    // Section 4a, item 1(b): a read refreshes (slides) the TTL -- it must not be left to coast
    // down to expiry while the system is actively being used. Initialize with a short TTL,
    // manually wind it down to simulate time passing, then prove a subsequent read pushes it
    // back up rather than leaving it to keep decaying.
    @Test
    void readRefreshesTheEpochTtl() {
        // A tiny window+TTL pair, not the real 15-minute access-token lifetime -- still
        // satisfies the constructor's own "epochTtl >= 2x epochWindow" validation (4s >= 2x2s),
        // without making this test wait out a real 15-minute window.
        RevocationChecker checker = checkerWithPassword(REDIS_PASSWORD, Duration.ofSeconds(2), Duration.ofSeconds(10));
        checker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60)); // init, TTL ~10s

        rawSetTtl("revocation-epoch", 2); // simulate most of the window having elapsed
        assertThat(rawTtlSeconds("revocation-epoch")).isLessThanOrEqualTo(2);

        checker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60)); // the read to test

        assertThat(rawTtlSeconds("revocation-epoch"))
                .as("a read must refresh (slide) the TTL back up, not leave it decaying toward "
                        + "the value we manually wound it down to")
                .isGreaterThan(2);
    }

    // Section 4a, item 1(c): refreshing the TTL must not perturb the epoch's own VALUE -- a
    // token issued after the epoch was established must still read as "not revoked" even after
    // the key's TTL has been refreshed by an intervening read, proving the refresh only touches
    // the key's lifetime, never the timestamp it stores.
    @Test
    void tokenIssuedAfterEpochStillNotRevokedAfterTtlRefresh() {
        RevocationChecker checker = checkerWithPassword(REDIS_PASSWORD, Duration.ofSeconds(2), Duration.ofSeconds(10));
        checker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60)); // establishes epoch ~= FIXED_NOW

        rawSetTtl("revocation-epoch", 2);
        checker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60)); // refreshes TTL, same epoch value
        assertThat(rawTtlSeconds("revocation-epoch")).isGreaterThan(2);

        Instant afterEpoch = FIXED_NOW.plusSeconds(5);
        assertThat(checker.isFamilyRevoked(UUID.randomUUID(), afterEpoch))
                .as("a token issued after the epoch must still read as not-revoked even once the "
                        + "epoch key's TTL has been refreshed by an intervening read")
                .isFalse();
    }

    // Failure test 10 (Section 5.10): a connection over TLS with the correct password succeeds
    // end to end.
    //
    // Deliberate exception to "nothing should pass right now": this test bypasses
    // RevocationChecker entirely (whose own isFamilyRevoked/revokeFamily methods are still RED
    // stubs that never touch Redis at all -- calling through them here would pass vacuously no
    // matter what the infrastructure actually does, which was the bug in the original version of
    // this test). Instead it performs a real SET then GET round-trip directly against the
    // TLS+auth Testcontainers Redis via a raw LettuceConnectionFactory, proving the TLS cert +
    // requirepass infrastructure itself genuinely works, independent of RevocationChecker's own
    // still-stubbed business logic. This is EXPECTED to legitimately pass.
    @Test
    void infrastructureTest_tlsConnectionWithCorrectPasswordSucceeds() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
                TLS_REDIS.getHost(), TLS_REDIS.getMappedPort(6380));
        config.setPassword(REDIS_PASSWORD);
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .useSsl().disablePeerVerification().and()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();

        String key = "tls-roundtrip-" + UUID.randomUUID();
        String value = "value-" + UUID.randomUUID();
        try {
            factory.getConnection().stringCommands().set(key.getBytes(), value.getBytes());
            byte[] readBack = factory.getConnection().stringCommands().get(key.getBytes());

            assertThat(readBack).isNotNull();
            assertThat(new String(readBack))
                    .as("a real SET then GET over TLS with the correct password must round-trip "
                            + "the exact value written")
                    .isEqualTo(value);
        } finally {
            factory.destroy();
        }
    }

    // Failure test 11 (Section 5.11): a wrong password fails fast (within the configured
    // timeout) and fails CLOSED -- the same RevocationCheckUnavailableException -> 503 path as
    // a network-level outage, not a different, more permissive outcome.
    @Test
    void wrongPasswordFailsFastAndFailsClosed() {
        RevocationChecker checker = checkerWithPassword("definitely-the-wrong-password");
        UUID familyId = UUID.randomUUID();

        long start = System.nanoTime();
        assertThatThrownBy(() -> checker.isFamilyRevoked(familyId, FIXED_NOW.minusSeconds(60)))
                .isInstanceOf(RevocationCheckUnavailableException.class);
        long elapsedMs = Duration.ofNanos(System.nanoTime() - start).toMillis();

        assertThat(elapsedMs)
                .as("a wrong password must fail fast, within a small multiple of the configured "
                        + "2-second command timeout, not hang indefinitely")
                .isLessThan(10_000);
    }

    // Failure test 7 (Section 5.7): Redis down (unreachable host/port) gives
    // RevocationCheckUnavailableException, never a value that would mean "not revoked" or
    // "revoked" as a guess.
    @Test
    void redisDownThrowsUnavailableException() throws IOException {
        int unreachablePort = findFreePort(); // nothing listens here
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration("127.0.0.1", unreachablePort);
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();
        RevocationChecker checker = new RevocationChecker(postgresDataSource(), factory, CLOCK, Duration.ofMinutes(15), Duration.ofHours(24));

        assertThatThrownBy(() -> checker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60)))
                .isInstanceOf(RevocationCheckUnavailableException.class);
    }

    // Failure test 12 (Section 5.12): neither the Redis password nor the full connection string
    // ever appears in any captured log line, OR in the thrown exception's own message/cause
    // chain, on BOTH the successful-TLS-connection path and the wrong-password failure path.
    // Driven through RevocationChecker.isFamilyRevoked itself (never a raw Lettuce call), since
    // that's the real call site a caller actually uses -- a leak in the exception message this
    // method throws would be just as real a leak as one in a log line.
    @Test
    void redisPasswordAndConnectionStringNeverAppearInLogsOrExceptionOnSuccessOrFailure(CapturedOutput output) {
        String fullConnectionStringShape = "rediss://default:" + REDIS_PASSWORD + "@"
                + TLS_REDIS.getHost() + ":" + TLS_REDIS.getMappedPort(6380);

        RevocationChecker successChecker = checkerWithPassword(REDIS_PASSWORD);
        successChecker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60));

        RevocationChecker failureChecker = checkerWithPassword("definitely-the-wrong-password");

        // The wrong-password call must actually fail (not silently return a yes/no answer) --
        // this is the assertion that fails against the current do-nothing stub, which never
        // touches Redis at all and so never throws anything here.
        Throwable thrown = org.assertj.core.api.Assertions.catchThrowable(
                () -> failureChecker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60)));
        assertThat(thrown)
                .as("a wrong password must fail the check, not silently return an answer")
                .isInstanceOf(RevocationCheckUnavailableException.class);

        // Walk the full cause chain -- a leaked secret could just as easily be wrapped three
        // levels down (e.g. Lettuce's own RedisCommandExecutionException naming the credential)
        // as sitting directly in the outermost message.
        Throwable cursor = thrown;
        while (cursor != null) {
            assertThat(cursor.getMessage())
                    .as("exception message at this level of the cause chain (%s) must never "
                            + "contain the real password", cursor.getClass().getName())
                    .doesNotContain(REDIS_PASSWORD)
                    .doesNotContain(fullConnectionStringShape);
            cursor = cursor.getCause();
        }

        // FIRST (of the log assertions): there must actually be SOME captured output to check at
        // all -- zero log lines would make "output doesn't contain the secret" trivially true
        // for the wrong reason, proving nothing about real logging discipline.
        assertThat(output.getAll())
                .as("the success and failure paths above must have produced at least one log line "
                        + "for this test to meaningfully prove the password/connection string are "
                        + "absent from it")
                .isNotBlank();

        assertThat(output.getAll())
                .as("the real password must never appear in captured output on either path")
                .doesNotContain(REDIS_PASSWORD);
        assertThat(output.getAll())
                .as("the full connection string shape (which embeds the password) must never appear")
                .doesNotContain(fullConnectionStringShape);
    }

    // Failure test 21 (Section 4a): Redis restart losing the revoked set entirely must not
    // silently re-accept a revoked access token -- the revocation-epoch mechanism must still
    // reject a still-unexpired, pre-loss token via 401-shaped rejection (isFamilyRevoked still
    // returns true), not silently "not revoked" once the direct evidence (the TTL'd key) is gone.
    @Test
    void redisDataLossDoesNotSilentlyReacceptRevokedToken() {
        RevocationChecker checker = checkerWithPassword(REDIS_PASSWORD);
        UUID familyId = UUID.randomUUID();
        Instant tokenIssuedAt = FIXED_NOW.minusSeconds(30);

        checker.revokeFamily(familyId);
        assertThat(checker.isFamilyRevoked(familyId, tokenIssuedAt))
                .as("immediately after revocation, the direct evidence (the TTL'd key) says revoked")
                .isTrue();

        // Simulate total Redis data loss (operator-triggered flush / eviction / restart losing
        // all data) -- the specific revoked:{familyId} key, AND the revocation-epoch marker
        // itself, are both gone.
        flushAllOn(checker);

        assertThat(checker.isFamilyRevoked(familyId, tokenIssuedAt))
                .as("even with the direct evidence gone, a token issued before the just-reset "
                        + "revocation-epoch must still be rejected -- proving the epoch mechanism "
                        + "catches what the lost key would have caught")
                .isTrue();

        // A token issued AFTER the new epoch is unaffected -- proving this isn't a blanket
        // "reject everything" but specifically age-relative-to-epoch.
        Instant freshTokenIssuedAt = FIXED_NOW.plusSeconds(5);
        assertThat(checker.isFamilyRevoked(UUID.randomUUID(), freshTokenIssuedAt))
                .as("a token issued after the new epoch, for an unrelated never-revoked family, "
                        + "must not be caught by the epoch check")
                .isFalse();
    }

    private void flushAllOn(RevocationChecker checker) {
        // Exercises the real Redis FLUSHALL against the same container the checker is bound to,
        // via a throwaway connection using the same credentials -- a real, total data loss, not
        // a mocked "pretend it's empty".
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
                TLS_REDIS.getHost(), TLS_REDIS.getMappedPort(6380));
        config.setPassword(REDIS_PASSWORD);
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .useSsl().disablePeerVerification().and()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();
        try {
            factory.getConnection().serverCommands().flushAll();
        } finally {
            factory.destroy();
        }
    }
}
