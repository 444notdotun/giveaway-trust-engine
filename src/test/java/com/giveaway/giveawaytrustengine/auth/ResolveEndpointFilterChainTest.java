package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.GiveawayTrustEngineApplication;
import com.giveaway.giveawaytrustengine.TestImages;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Slice 3 (Auth), Section 5, failure tests 3/4/7/9/21 -- exercised through the REAL application
 * context and the REAL filter chain (not a unit test against a hand-built filter instance), per
 * the plan's own instruction that "the first slice that adds a real resolve endpoint should
 * re-prove this against that actual endpoint, not just trust this slice's component-level proof
 * transitively". This test uses the test-only {@code GET /resolve/ping} endpoint (see
 * {@code ResolvePingController}) as that stand-in.
 *
 * Two separate application contexts, deliberately: one with a REAL, reachable Redis (so the
 * missing/expired/revoked -> 401 tests aren't confounded by Redis also being down), and one with
 * Redis pointed at an unreachable address (isolating the Redis-down -> 503 case). Same pattern
 * as every other full-app test in this project (Postgres always real via Testcontainers).
 *
 * RED: {@link JwtService#verifyAccessToken(String)} always throws regardless of the token's
 * actual validity, and {@link RevocationChecker#isFamilyRevoked(UUID, Instant)} always returns
 * {@code false} without ever touching Redis -- every assertion here names what it actually
 * observed, not just "any non-200".
 */
@Testcontainers
class ResolveEndpointFilterChainTest {

    private static final String SIGNING_KEY = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
    private static final Instant FIXED_NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("giveaway_trust_engine_test")
            .withUsername("test")
            .withPassword("test");

    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse(TestImages.REDIS))
            .withExposedPorts(6379);

    static ConfigurableApplicationContext appWithRedisUp;
    static ConfigurableApplicationContext appWithRedisDown;
    static int portWithRedisUp;
    static int portWithRedisDown;

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @BeforeAll
    static void startEverything() throws Exception {
        POSTGRES.start();
        REDIS.start();

        int unreachableRedisPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            unreachableRedisPort = socket.getLocalPort(); // nothing listens here once closed
        }

        appWithRedisUp = buildApp(REDIS.getHost(), REDIS.getMappedPort(6379));
        portWithRedisUp = appWithRedisUp.getEnvironment().getProperty("local.server.port", Integer.class);

        appWithRedisDown = buildApp("127.0.0.1", unreachableRedisPort);
        portWithRedisDown = appWithRedisDown.getEnvironment().getProperty("local.server.port", Integer.class);
    }

    private static ConfigurableApplicationContext buildApp(String redisHost, int redisPort) {
        ConfigurableApplicationContext context = new SpringApplicationBuilder(GiveawayTrustEngineApplication.class)
                .web(WebApplicationType.SERVLET)
                .run(
                        "--server.port=0",
                        "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "--spring.datasource.username=" + POSTGRES.getUsername(),
                        "--spring.datasource.password=" + POSTGRES.getPassword(),
                        "--spring.data.redis.host=" + redisHost,
                        "--spring.data.redis.port=" + redisPort,
                        "--spring.data.redis.timeout=1000",
                        "--spring.data.redis.connect-timeout=1000",
                        "--app.environment=DEV",
                        "--app.bachs.sandbox-base-url=https://sandbox-api.bachs.io",
                        "--app.bachs.live-base-url=https://api.bachs.io",
                        "--app.bachs.base-url=https://sandbox-api.bachs.io",
                        "--app.jwt.signing-key=" + SIGNING_KEY,
                        "--app.x-oauth.client-id=test-client-id",
                        "--app.x-oauth.client-secret=test-client-secret",
                        "--app.x-oauth.redirect-uri=http://localhost/auth/callback",
                        "--app.x-oauth.authorize-url=https://x.com/i/oauth2/authorize",
                        "--app.x-oauth.token-url=http://127.0.0.1:1/2/oauth2/token",
                        "--app.x-oauth.user-lookup-url=http://127.0.0.1:1/2/users/me",
                        "--app.x-oauth.connect-timeout=500ms",
                        "--app.x-oauth.request-timeout=500ms");
        return context;
    }

    @AfterAll
    static void stopEverything() {
        if (appWithRedisUp != null) {
            appWithRedisUp.close();
        }
        if (appWithRedisDown != null) {
            appWithRedisDown.close();
        }
        REDIS.stop();
        POSTGRES.stop();
    }

    private HttpResponse<String> ping(int port, String cookieValue) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/resolve/ping"))
                .GET();
        if (cookieValue != null) {
            builder.header("Cookie", "accessToken=" + cookieValue);
        }
        return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    // Failure test 7 (Section 5.7): Redis down must give 503 through the REAL filter chain, not
    // a silent 200 ("not revoked" guessed) nor a 401.
    @Test
    void redisDownOnResolveStyleEndpointReturns503() throws Exception {
        HttpResponse<String> response = ping(portWithRedisDown, null);

        assertThat(response.statusCode())
                .as("real observed status with Redis unreachable -- expected 503; "
                        + "RevocationChecker.isFamilyRevoked is currently a stub that always "
                        + "returns false without ever touching Redis, so 200 is the realistic "
                        + "wrong answer to expect here today")
                .isEqualTo(503);
    }

    // Failure test 9 (Section 5.9) / missing-token case: no accessToken cookie at all must be
    // rejected with 401, never silently treated as an anonymous success. Uses the Redis-UP app
    // so this isn't confounded by the separate Redis-down case above.
    @Test
    void missingTokenOnResolveStyleEndpointReturns401() throws Exception {
        HttpResponse<String> response = ping(portWithRedisUp, null);

        assertThat(response.statusCode())
                .as("real observed status with no accessToken cookie at all (Redis reachable) -- "
                        + "expected 401; the current ping endpoint has no missing-token check of "
                        + "its own and falls through to calling isFamilyRevoked with a stand-in "
                        + "id, so 200 is the realistic wrong answer to expect here today")
                .isEqualTo(401);
    }

    // Failure test 4 (Section 5.4): an expired access token must be rejected with 401 through
    // the real filter chain.
    @Test
    void expiredAccessTokenOnResolveStyleEndpointReturns401() throws Exception {
        JwtService expiredTokenIssuer = new JwtService(
                SIGNING_KEY, Clock.fixed(FIXED_NOW.minus(Duration.ofHours(1)), ZoneOffset.UTC));
        String expiredShapedToken = expiredTokenIssuer.issueAccessToken(UUID.randomUUID(), UUID.randomUUID());

        HttpResponse<String> response = ping(portWithRedisUp, expiredShapedToken);

        assertThat(response.statusCode())
                .as("real observed status for an expired-shaped access token -- expected 401; "
                        + "JwtAuthenticationFilter currently lets JwtVerificationException "
                        + "propagate UNCAUGHT from doFilter (before DispatcherServlet ever runs), "
                        + "so AuthExceptionHandlers's @ExceptionHandler never actually gets a "
                        + "chance to run for this path -- a 500-shaped response (not 401) is the "
                        + "realistic wrong answer to expect here today")
                .isEqualTo(401);
    }

    // Failure test 3/21 combination (Section 5.3 / Section 4a): a token belonging to an
    // already-(attempted-to-be)-revoked family must be rejected with 401 through the real
    // filter chain.
    @Test
    void revokedFamilyAccessTokenOnResolveStyleEndpointReturns401() throws Exception {
        UUID cmId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        JwtService tokenIssuer = new JwtService(SIGNING_KEY, CLOCK);
        String tokenForRevokedFamily = tokenIssuer.issueAccessToken(cmId, familyId);

        // Attempt to revoke the family up front -- currently a no-op, so this has no real effect
        // yet, consistent with every other RevocationChecker RED test in this slice.
        RevocationChecker revocationChecker = appWithRedisUp.getBean(RevocationChecker.class);
        revocationChecker.revokeFamily(familyId);

        HttpResponse<String> response = ping(portWithRedisUp, tokenForRevokedFamily);

        assertThat(response.statusCode())
                .as("real observed status for a token whose family was (attempted to be) "
                        + "revoked -- expected 401; same uncaught-exception-from-the-filter gap "
                        + "as the expired-token case above makes a 500-shaped response the "
                        + "realistic wrong answer to expect here today")
                .isEqualTo(401);
    }
}
