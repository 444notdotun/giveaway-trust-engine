package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.GiveawayTrustEngineApplication;
import com.giveaway.giveawaytrustengine.TestImages;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chunk 4 review, item 2: Redis being unreachable must give a clean 503 on BOTH
 * {@code /auth/login} and {@code /auth/callback} -- never a raw, unhandled 500 -- and the WARN
 * log this emits must carry a failure-reason category only, never the real {@code state},
 * {@code code}, or any token value.
 *
 * Same pattern as {@code ResolveEndpointFilterChainTest}: a second full application context
 * pointed at an address nothing listens on, isolating "Redis specifically is unreachable" from
 * every other failure mode. Postgres is still real (Testcontainers) since neither endpoint under
 * test here ever reaches the database -- the Redis failure is hit before any DB call.
 */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
class OAuthRedisUnavailableTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("giveaway_trust_engine_test")
            .withUsername("test")
            .withPassword("test");

    static ConfigurableApplicationContext appWithRedisDown;
    static int appPort;

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @BeforeAll
    static void startEverything() throws Exception {
        POSTGRES.start();

        int unreachableRedisPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            unreachableRedisPort = socket.getLocalPort(); // nothing listens here once closed
        }

        appWithRedisDown = new SpringApplicationBuilder(GiveawayTrustEngineApplication.class)
                .web(WebApplicationType.SERVLET)
                .run(
                        "--server.port=0",
                        "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "--spring.datasource.username=" + POSTGRES.getUsername(),
                        "--spring.datasource.password=" + POSTGRES.getPassword(),
                        "--spring.data.redis.host=127.0.0.1",
                        "--spring.data.redis.port=" + unreachableRedisPort,
                        "--spring.data.redis.password=fake-redis-password",
                        "--spring.data.redis.timeout=1000",
                        "--spring.data.redis.connect-timeout=1000",
                        "--app.environment=DEV",
                        "--app.bachs.sandbox-base-url=https://sandbox-api.bachs.io",
                        "--app.bachs.live-base-url=https://api.bachs.io",
                        "--app.bachs.base-url=https://sandbox-api.bachs.io",
                        "--app.jwt.signing-key=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
                        "--app.x-oauth.client-id=test-client-id",
                        "--app.x-oauth.client-secret=test-client-secret",
                        "--app.x-oauth.redirect-uri=http://localhost/auth/callback",
                        "--app.x-oauth.authorize-url=https://x.com/i/oauth2/authorize",
                        "--app.x-oauth.token-url=http://127.0.0.1:1/2/oauth2/token",
                        "--app.x-oauth.user-lookup-url=http://127.0.0.1:1/2/users/me",
                        "--app.x-oauth.connect-timeout=500ms",
                        "--app.x-oauth.request-timeout=500ms");
        appPort = appWithRedisDown.getEnvironment().getProperty("local.server.port", Integer.class);
    }

    @AfterAll
    static void stopEverything() {
        if (appWithRedisDown != null) {
            appWithRedisDown.close();
        }
        POSTGRES.stop();
    }

    private String baseUri() {
        return "http://localhost:" + appPort;
    }

    @Test
    void loginReturns503WhenRedisUnavailable(CapturedOutput output) throws Exception {
        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appWithRedisDown.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double failuresBefore = meterRegistry.counter("giveaway.auth.failure", "reason", "redis-unavailable").count();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUri() + "/auth/login"))
                .GET()
                .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode())
                .as("Redis unreachable on /auth/login must give a clean 503, never a raw 500")
                .isEqualTo(503);
        assertThat(response.body()).as("generic empty body, no detail leaked").isEmpty();
        assertThat(response.headers().firstValue("Location"))
                .as("no redirect to X when the state could never be stored")
                .isEmpty();

        assertThat(output.getAll())
                .as("the failure-reason log must name the category, never a token/secret value")
                .contains("redis-unavailable");
        // Chunk 4 review (final round), item 2: one counter name for every auth failure --
        // giveaway.auth.failure, not a separate giveaway.oauth.failure for this controller.
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "redis-unavailable").count())
                .isGreaterThan(failuresBefore);
    }

    @Test
    void callbackReturns503WhenRedisUnavailableAndLogsNoStateOrCode(CapturedOutput output) throws Exception {
        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appWithRedisDown.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double failuresBefore = meterRegistry.counter("giveaway.auth.failure", "reason", "redis-unavailable").count();

        String state = "state-" + UUID.randomUUID();
        String code = "code-" + UUID.randomUUID();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUri() + "/auth/callback?code=" + code + "&state=" + state))
                .GET()
                .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode())
                .as("Redis unreachable on /auth/callback must give a clean 503, never a raw 500")
                .isEqualTo(503);
        assertThat(response.body()).as("generic empty body, no detail leaked").isEmpty();

        assertThat(output.getAll())
                .as("the real state value must never appear in any captured log line")
                .doesNotContain(state);
        assertThat(output.getAll())
                .as("the real code value must never appear in any captured log line")
                .doesNotContain(code);
        assertThat(output.getAll())
                .as("the failure-reason log must name the category, never a token/secret value")
                .contains("redis-unavailable");
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "redis-unavailable").count())
                .isGreaterThan(failuresBefore);
    }
}
