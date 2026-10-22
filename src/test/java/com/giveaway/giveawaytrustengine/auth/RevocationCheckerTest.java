package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.TestImages;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
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

    @BeforeAll
    static void startTlsRedis() throws Exception {
        certDir = Files.createTempDirectory("revocation-checker-tls");
        generateSelfSignedCertWithRedisHelper(certDir);

        TLS_REDIS = new GenericContainer<>(DockerImageName.parse(TestImages.REDIS))
                .withExposedPorts(6380)
                .withCopyFileToContainer(MountableFile.forHostPath(certDir), "/tls")
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

    @AfterAll
    static void stopTlsRedis() {
        if (TLS_REDIS != null) {
            TLS_REDIS.stop();
        }
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
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(
                TLS_REDIS.getHost(), TLS_REDIS.getMappedPort(6380));
        config.setPassword(password);
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
                .useSsl().disablePeerVerification()
                .commandTimeout(Duration.ofSeconds(2))
                .build();
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, clientConfig);
        factory.afterPropertiesSet();
        return new RevocationChecker(factory, CLOCK, Duration.ofMinutes(15));
    }

    // Failure test 10 (Section 5.10): a connection over TLS with the correct password succeeds
    // end to end -- a real revocation-check read completes successfully.
    @Test
    void tlsConnectionWithCorrectPasswordSucceeds() {
        RevocationChecker checker = checkerWithPassword(REDIS_PASSWORD);
        UUID familyId = UUID.randomUUID();

        boolean revoked = checker.isFamilyRevoked(familyId, FIXED_NOW.minusSeconds(60));

        assertThat(revoked).as("a family never revoked must read back as not revoked").isFalse();
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
        RevocationChecker checker = new RevocationChecker(factory, CLOCK, Duration.ofMinutes(15));

        assertThatThrownBy(() -> checker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60)))
                .isInstanceOf(RevocationCheckUnavailableException.class);
    }

    // Failure test 12 (Section 5.12): neither the Redis password nor the full connection string
    // ever appears in any captured log line, on BOTH the successful-TLS-connection path and the
    // wrong-password failure path.
    @Test
    void redisPasswordAndConnectionStringNeverAppearInLogsOnSuccessOrFailure(CapturedOutput output) {
        String fullConnectionStringShape = "rediss://default:" + REDIS_PASSWORD + "@"
                + TLS_REDIS.getHost() + ":" + TLS_REDIS.getMappedPort(6380);

        RevocationChecker successChecker = checkerWithPassword(REDIS_PASSWORD);
        successChecker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60));

        RevocationChecker failureChecker = checkerWithPassword("definitely-the-wrong-password");
        try {
            failureChecker.isFamilyRevoked(UUID.randomUUID(), FIXED_NOW.minusSeconds(60));
        } catch (RevocationCheckUnavailableException expected) {
            // expected on this path
        }

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
                .useSsl().disablePeerVerification()
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
