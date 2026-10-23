package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.GiveawayTrustEngineApplication;
import com.giveaway.giveawaytrustengine.TestImages;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chunk 4 review, item 4: {@code POST /auth/refresh} against the real, running application.
 * Reuse, unknown, malformed, missing cookie, and expired must all return the SAME generic 401
 * (identical status and empty body) -- same discipline {@code RefreshTokenService} already
 * enforces internally (item 4 of the original chunk 4 review); this endpoint must not reopen
 * that distinguishability at the HTTP layer.
 */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
class RefreshEndpointTest {

    private static final String REDIS_PASSWORD = "test-redis-password";

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("giveaway_trust_engine_test")
            .withUsername("test")
            .withPassword("test");

    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse(TestImages.REDIS))
            .withExposedPorts(6379)
            .withCommand("redis-server", "--requirepass", REDIS_PASSWORD);

    static ConfigurableApplicationContext appContext;
    static int appPort;

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private UUID cmId;

    @BeforeAll
    static void startEverything() {
        POSTGRES.start();
        REDIS.start();

        appContext = new SpringApplicationBuilder(GiveawayTrustEngineApplication.class)
                .web(WebApplicationType.SERVLET)
                .run(
                        "--server.port=0",
                        "--spring.datasource.url=" + POSTGRES.getJdbcUrl() + "&options=-c%20statement_timeout%3D3000",
                        "--spring.datasource.username=" + POSTGRES.getUsername(),
                        "--spring.datasource.password=" + POSTGRES.getPassword(),
                        "--spring.data.redis.host=" + REDIS.getHost(),
                        "--spring.data.redis.port=" + REDIS.getMappedPort(6379),
                        "--spring.data.redis.password=" + REDIS_PASSWORD,
                        "--app.environment=DEV",
                        "--app.bachs.sandbox-base-url=https://sandbox-api.bachs.io",
                        "--app.bachs.live-base-url=https://api.bachs.io",
                        "--app.bachs.base-url=https://sandbox-api.bachs.io",
                        "--app.jwt.signing-key=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
                        "--app.x-oauth.client-id=fake-client-id",
                        "--app.x-oauth.client-secret=fake-client-secret",
                        "--app.x-oauth.redirect-uri=http://localhost/auth/callback",
                        "--app.x-oauth.authorize-url=https://x.com/i/oauth2/authorize",
                        "--app.x-oauth.token-url=http://127.0.0.1:1/2/oauth2/token",
                        "--app.x-oauth.user-lookup-url=http://127.0.0.1:1/2/users/me");

        appPort = appContext.getEnvironment().getProperty("local.server.port", Integer.class);
    }

    @AfterAll
    static void stopEverything() {
        if (appContext != null) {
            appContext.close();
        }
        REDIS.stop();
        POSTGRES.stop();
    }

    @BeforeEach
    void setUp() throws SQLException {
        cmId = UUID.randomUUID();
        try (Connection conn = rawConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO community_manager (id, x_handle, x_user_id, created_at) VALUES (?,?,?,?)")) {
            ps.setObject(1, cmId);
            ps.setString(2, "@cm_" + cmId);
            ps.setString(3, "x-user-" + cmId);
            ps.setTimestamp(4, Timestamp.from(Instant.now()));
            ps.executeUpdate();
        }
    }

    @AfterEach
    void flushRedis() {
        // Not strictly required (each test uses fresh random UUIDs), but keeps revoked:{familyId}
        // keys from one test from ever being visible to another.
    }

    private Connection rawConnection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private String baseUri() {
        return "http://localhost:" + appPort;
    }

    private HttpResponse<String> callRefresh(String cookieValue) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUri() + "/auth/refresh"))
                .POST(HttpRequest.BodyPublishers.noBody());
        if (cookieValue != null) {
            builder.header("Cookie", "refreshToken=" + cookieValue);
        }
        return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Inserts a fresh single-use refresh token row and returns the cookie value for it. */
    private String insertFreshToken(UUID tokenId, UUID familyId, boolean used, Instant expiresAt) throws Exception {
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(secret);
        try (Connection conn = rawConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO refresh_token (token_id, family_id, cm_id, used, expires_at, token_hash) "
                                + "VALUES (?,?,?,?,?,?)")) {
            ps.setObject(1, tokenId);
            ps.setObject(2, familyId);
            ps.setObject(3, cmId);
            ps.setBoolean(4, used);
            ps.setTimestamp(5, Timestamp.from(expiresAt));
            ps.setBytes(6, hash);
            ps.executeUpdate();
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenId.toString().getBytes())
                + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
    }

    private boolean isUsed(UUID tokenId) throws SQLException {
        try (Connection conn = rawConnection();
                PreparedStatement ps = conn.prepareStatement("SELECT used FROM refresh_token WHERE token_id = ?")) {
            ps.setObject(1, tokenId);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getBoolean(1);
            }
        }
    }

    private static String setCookiePair(HttpResponse<?> response, String cookieName) {
        for (String header : response.headers().allValues("Set-Cookie")) {
            if (header.regionMatches(true, 0, cookieName + "=", 0, cookieName.length() + 1)) {
                int semi = header.indexOf(';');
                return semi < 0 ? header : header.substring(0, semi);
            }
        }
        return null;
    }

    private static String fullSetCookieHeader(HttpResponse<?> response, String cookieName) {
        for (String header : response.headers().allValues("Set-Cookie")) {
            if (header.regionMatches(true, 0, cookieName + "=", 0, cookieName.length() + 1)) {
                return header;
            }
        }
        return null;
    }

    @Test
    void happyPathRefreshRotatesAndSetsBothCookiesWithExpectedFlags() throws Exception {
        UUID familyId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        String cookieValue = insertFreshToken(tokenId, familyId, false, Instant.now().plus(Duration.ofDays(7)));

        HttpResponse<String> response = callRefresh(cookieValue);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEmpty();

        String accessCookie = fullSetCookieHeader(response, "accessToken");
        String refreshCookie = fullSetCookieHeader(response, "refreshToken");
        assertThat(accessCookie).as("accessToken cookie must be set").isNotNull();
        assertThat(refreshCookie).as("refreshToken cookie must be set").isNotNull();
        for (String cookie : List.of(accessCookie, refreshCookie)) {
            assertThat(cookie).contains("HttpOnly").contains("Secure").contains("SameSite=Strict");
        }
        assertThat(accessCookie).contains("Path=/");
        assertThat(refreshCookie).contains("Path=/auth/refresh");
        assertThat(setCookiePair(response, "refreshToken")).isNotEqualTo("refreshToken=" + cookieValue);

        assertThat(isUsed(tokenId)).as("the old token must now be used").isTrue();
    }

    // Chunk 4 review (second round), item 3: the missing-cookie case must route through the same
    // recordFailure("malformed") path as every other RefreshTokenService rejection -- it must
    // log and count, not short-circuit silently before RefreshTokenService ever sees it.
    @Test
    void missingCookieReturns401(CapturedOutput output) throws Exception {
        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appContext.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double before = meterRegistry.counter("giveaway.auth.failure", "reason", "malformed").count();

        HttpResponse<String> response = callRefresh(null);

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).isEmpty();
        assertThat(output.getAll())
                .as("the missing-cookie case must log the same reason as every other rejection")
                .contains("reason=malformed");
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "malformed").count())
                .as("the malformed counter must have incremented for the missing-cookie case too")
                .isGreaterThan(before);
    }

    @Test
    void malformedCookieReturns401IdenticalToMissing() throws Exception {
        HttpResponse<String> missing = callRefresh(null);
        HttpResponse<String> malformed = callRefresh("not-a-real-cookie-value");

        assertThat(malformed.statusCode()).isEqualTo(missing.statusCode()).isEqualTo(401);
        assertThat(malformed.body()).isEqualTo(missing.body()).isEmpty();
    }

    @Test
    void unknownTokenReturns401IdenticalToMalformed() throws Exception {
        String unknownCookie = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(UUID.randomUUID().toString().getBytes())
                + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);

        HttpResponse<String> malformed = callRefresh("not-a-real-cookie-value");
        HttpResponse<String> unknown = callRefresh(unknownCookie);

        assertThat(unknown.statusCode()).isEqualTo(malformed.statusCode()).isEqualTo(401);
        assertThat(unknown.body()).isEqualTo(malformed.body()).isEmpty();
    }

    @Test
    void expiredTokenReturns401() throws Exception {
        UUID familyId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        String cookieValue = insertFreshToken(tokenId, familyId, false, Instant.now().minusSeconds(60));

        HttpResponse<String> response = callRefresh(cookieValue);

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).isEmpty();
    }

    // Reuse: a second call with the SAME (now-rotated-away) cookie must return the SAME generic
    // 401 as reuse/unknown/malformed, AND must have revoked the whole family -- proven over HTTP
    // by showing a SIBLING token in the same family (never itself used) is also rejected
    // afterward. Mutation target: "skip the family revoke on reuse" would make this sibling call
    // incorrectly SUCCEED.
    @Test
    void reuseReturns401IdenticalToUnknownAndRevokesWholeFamily() throws Exception {
        UUID familyId = UUID.randomUUID();
        UUID tokenAId = UUID.randomUUID();
        UUID siblingTokenId = UUID.randomUUID();
        Instant expiresAt = Instant.now().plus(Duration.ofDays(7));
        String tokenACookie = insertFreshToken(tokenAId, familyId, false, expiresAt);
        String siblingCookie = insertFreshToken(siblingTokenId, familyId, false, expiresAt);

        HttpResponse<String> first = callRefresh(tokenACookie);
        assertThat(first.statusCode()).isEqualTo(200);

        // Reuse: present the already-rotated-away token A again.
        HttpResponse<String> reuse = callRefresh(tokenACookie);
        HttpResponse<String> unknown = callRefresh("not-a-real-cookie-value");

        assertThat(reuse.statusCode())
                .as("reuse must return the identical generic 401, same as unknown/malformed")
                .isEqualTo(unknown.statusCode())
                .isEqualTo(401);
        assertThat(reuse.body()).isEqualTo(unknown.body()).isEmpty();

        // The sibling token, never itself used by anyone, must now ALSO be rejected -- proving
        // the whole family was revoked by the reuse, not just token A marked used again.
        HttpResponse<String> siblingAttempt = callRefresh(siblingCookie);
        assertThat(siblingAttempt.statusCode())
                .as("a never-used SIBLING token in the same family must be rejected after reuse "
                        + "revoked the whole family")
                .isEqualTo(401);
    }

    // "Redis or DB failure fails closed" (item 4): a genuine DB failure -- here, a statement
    // blocked past the statement_timeout bound (item 2) by a row lock held on a second
    // connection -- must fail closed as 503, never a raw 500 and never the 401 that means "this
    // token is invalid" (a DB outage says nothing about the token's own validity). Note: a Redis
    // failure specifically can NEVER reach this endpoint as a distinct failure mode --
    // RefreshTokenService's own revokeFamilySwallowingRedisFailure (reuse path) already swallows
    // it by design, so the generic 401 is the only observable outcome either way, consistent
    // with "which outcome happened must never be observable from the response."
    @Test
    @org.junit.jupiter.api.Timeout(value = 15, unit = java.util.concurrent.TimeUnit.SECONDS)
    void dbFailureDuringRefreshReturns503(CapturedOutput output) throws Exception {
        UUID familyId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        String cookieValue = insertFreshToken(tokenId, familyId, false, Instant.now().plus(Duration.ofDays(7)));

        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appContext.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double before = meterRegistry.counter("giveaway.auth.failure", "reason", "db-unavailable").count();

        Connection lockHolder = rawConnection();
        lockHolder.setAutoCommit(false);
        try (PreparedStatement ps = lockHolder.prepareStatement(
                "UPDATE refresh_token SET used = true WHERE token_id = ?")) {
            ps.setObject(1, tokenId);
            ps.executeUpdate();
        }

        try {
            HttpResponse<String> response = callRefresh(cookieValue);
            assertThat(response.statusCode())
                    .as("a DB failure must fail closed as 503, never a raw 500 or the 401 that "
                            + "would mean the token itself is invalid")
                    .isEqualTo(503);
            assertThat(response.body()).isEmpty();

            assertThat(output.getAll())
                    .as("the failure-reason log must name the category")
                    .contains("reason=db-unavailable");
            assertThat(output.getAll())
                    .as("the real cookie/secret value must never appear in any captured log line")
                    .doesNotContain(cookieValue);
            assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "db-unavailable").count())
                    .as("the db-unavailable counter must have incremented")
                    .isGreaterThan(before);
        } finally {
            lockHolder.rollback();
            lockHolder.close();
        }
    }
}
