package com.giveaway.giveawaytrustengine.auth;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.VerificationException;
import com.github.tomakehurst.wiremock.matching.RequestPatternBuilder;
import com.giveaway.giveawaytrustengine.GiveawayTrustEngineApplication;
import com.giveaway.giveawaytrustengine.TestImages;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Slice 3 (Auth), Section 0 (OAuth login flow) and Section 5 (failure tests 13-20) + the OAuth
 * login happy path (Tests summary).
 * Plan doc: docs/slices/03-auth.md.
 *
 * RED: no {@code OAuthLoginController} (or equivalent), no {@code XOAuthClient}, no
 * {@code CommunityManager} JPA entity exist yet -- every test here is expected to fail against
 * the real application context either at startup (missing beans/properties) or at request time
 * (404/500 instead of the real behavior).
 *
 * Boots the REAL application (Testcontainers Postgres + Redis, both load-bearing, not excluded)
 * against WireMock-mocked X token-exchange and user-lookup endpoints -- this project's
 * established external-call test pattern. No redirects are followed automatically
 * ({@code HttpClient.Redirect.NEVER}) so the {@code state} value and cookies can be inspected
 * directly, matching every prior slice's "assert the real HTTP response" standard.
 */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
class OAuthLoginFlowTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("giveaway_trust_engine_test")
            .withUsername("test")
            .withPassword("test");

    private static final String REDIS_PASSWORD = "test-redis-password";

    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse(TestImages.REDIS))
            .withExposedPorts(6379)
            .withCommand("redis-server", "--requirepass", REDIS_PASSWORD);

    static WireMockServer wireMock;
    static ConfigurableApplicationContext appContext;
    static int appPort;

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @BeforeAll
    static void startEverything() {
        POSTGRES.start();
        REDIS.start();
        wireMock = new WireMockServer(0);
        wireMock.start();

        appContext = new SpringApplicationBuilder(GiveawayTrustEngineApplication.class)
                .web(WebApplicationType.SERVLET)
                .run(
                        "--server.port=0",
                        "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "--spring.datasource.username=" + POSTGRES.getUsername(),
                        "--spring.datasource.password=" + POSTGRES.getPassword(),
                        "--spring.datasource.hikari.connection-init-sql=SET statement_timeout=3000",
                        "--spring.data.redis.host=" + REDIS.getHost(),
                        "--spring.data.redis.port=" + REDIS.getMappedPort(6379),
                        "--spring.data.redis.password=" + REDIS_PASSWORD,
                        "--app.environment=DEV",
                        "--app.bachs.sandbox-base-url=https://sandbox-api.bachs.io",
                        "--app.bachs.live-base-url=https://api.bachs.io",
                        "--app.bachs.base-url=https://sandbox-api.bachs.io",
                        "--app.jwt.signing-key=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
                        "--app.x-oauth.client-id=test-client-id",
                        "--app.x-oauth.client-secret=test-client-secret",
                        "--app.x-oauth.redirect-uri=http://localhost/auth/callback",
                        "--app.x-oauth.authorize-url=https://x.com/i/oauth2/authorize",
                        "--app.x-oauth.token-url=" + wireMock.baseUrl() + "/2/oauth2/token",
                        "--app.x-oauth.user-lookup-url=" + wireMock.baseUrl() + "/2/users/me",
                        // Chunk 4 review (final round), item 4: was 500ms -- too tight a margin
                        // against real scheduling jitter on a loopback call to the embedded
                        // WireMock server under a loaded test run (the whole Maven suite running
                        // many Testcontainers-backed classes), which could occasionally trip this
                        // deadline before the TCP connect to WireMock even completed, so WireMock
                        // never saw the request at all (zero journal entries, not a slow one).
                        // Matches the production default (application.properties) instead of an
                        // artificially tight value chosen only to keep this test fast.
                        "--app.x-oauth.connect-timeout=2000ms",
                        "--app.x-oauth.request-timeout=2000ms");

        appPort = appContext.getEnvironment().getProperty("local.server.port", Integer.class);
    }

    @AfterAll
    static void stopEverything() {
        if (appContext != null) {
            appContext.close();
        }
        if (wireMock != null) {
            wireMock.stop();
        }
        REDIS.stop();
        POSTGRES.stop();
    }

    @AfterEach
    void resetStubs() {
        wireMock.resetAll();
    }

    /**
     * Chunk 4 review (final round), item 4: a bounded, polling wait for WireMock's request
     * journal, not a single immediate check -- by the time the app's HTTP call returns, the
     * request it sent has already been journaled by WireMock (requests are recorded on receipt,
     * before the configured response delay is even applied), so this is purely defensive against
     * any eventual-consistency lag in WireMock's own journal rather than the mechanism the
     * previously-observed flake traced back to (see the 2000ms connect/request-timeout comment
     * above -- that was the real fix). No fixed sleep: this returns the instant the request shows
     * up, and only blocks the full bound if it never does.
     */
    private static void awaitWireMockRequest(RequestPatternBuilder pattern) {
        long deadlineNanos = System.nanoTime() + Duration.ofSeconds(2).toNanos();
        while (true) {
            try {
                wireMock.verify(pattern);
                return;
            }
            catch (VerificationException stillMissing) {
                if (System.nanoTime() >= deadlineNanos) {
                    throw stillMissing;
                }
            }
            try {
                Thread.sleep(25);
            }
            catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted while awaiting a WireMock request", interrupted);
            }
        }
    }

    private String baseUri() {
        return "http://localhost:" + appPort;
    }

    private HttpResponse<Void> startLogin() throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUri() + "/auth/login"))
                .GET()
                .build();
        return HTTP.send(request, HttpResponse.BodyHandlers.discarding());
    }

    private HttpResponse<String> callback(String query) throws IOException, InterruptedException {
        return callback(query, null);
    }

    /** {@code cookieHeaderValue} is a raw {@code name=value} pair (or several, "; "-joined), or null for none. */
    private HttpResponse<String> callback(String query, String cookieHeaderValue) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUri() + "/auth/callback?" + query))
                .GET();
        if (cookieHeaderValue != null) {
            builder.header("Cookie", cookieHeaderValue);
        }
        return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * A fresh, unique, purely-numeric X user id (chunk 4 review, item 4: the real
     * {@code XOAuthClient} now validates X's own {@code id} against {@code ^[0-9]{1,20}$}, so
     * these test fixtures must look like plausible X ids, not an arbitrary label).
     */
    private static String uniqueNumericXUserId() {
        return Long.toUnsignedString(java.util.concurrent.ThreadLocalRandom.current().nextLong());
    }

    /** Extracts the raw {@code name=value} pair for one cookie from a response's Set-Cookie headers. */
    private static String setCookiePair(HttpResponse<?> response, String cookieName) {
        String full = fullSetCookieHeader(response, cookieName);
        if (full == null) {
            return null;
        }
        int semi = full.indexOf(';');
        return semi < 0 ? full : full.substring(0, semi);
    }

    /** Extracts the full Set-Cookie header line (all attributes) for one cookie from a response. */
    private static String fullSetCookieHeader(HttpResponse<?> response, String cookieName) {
        for (String header : response.headers().allValues("Set-Cookie")) {
            if (header.regionMatches(true, 0, cookieName + "=", 0, cookieName.length() + 1)) {
                return header;
            }
        }
        return null;
    }

    private static String queryParam(String url, String key) {
        String marker = key + "=";
        int idx = url.indexOf(marker);
        if (idx < 0) {
            return null;
        }
        int start = idx + marker.length();
        int end = url.indexOf('&', start);
        String raw = end < 0 ? url.substring(start) : url.substring(start, end);
        return java.net.URLDecoder.decode(raw, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Reads the raw Redis value stored for a state: {@code codeVerifier + ":" + bindingHashHex}
     * (item 1's binding-cookie fix). Returns null if the key doesn't exist.
     */
    private String readStoredStateValue(String state) {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        config.setPassword(REDIS_PASSWORD);
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, LettuceClientConfiguration.builder()
                .commandTimeout(Duration.ofSeconds(2)).build());
        factory.afterPropertiesSet();
        try {
            byte[] value = factory.getConnection().stringCommands()
                    .get(("oauth:state:" + state).getBytes());
            return value == null ? null : new String(value);
        } finally {
            factory.destroy();
        }
    }

    /** Reads the single-use PKCE verifier this app stored server-side in Redis for a state. */
    private String readStoredVerifier(String state) {
        String stored = readStoredStateValue(state);
        if (stored == null) {
            return null;
        }
        int idx = stored.indexOf(':');
        return idx < 0 ? stored : stored.substring(0, idx);
    }

    /** Corrupts only the verifier half of the stored value, preserving the binding hash half. */
    private void overwriteStoredVerifier(String state, String newVerifier) {
        String stored = readStoredStateValue(state);
        int idx = stored.indexOf(':');
        String bindingHashHex = idx < 0 ? "" : stored.substring(idx + 1);
        String newStoredValue = newVerifier + ":" + bindingHashHex;

        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        config.setPassword(REDIS_PASSWORD);
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, LettuceClientConfiguration.builder()
                .commandTimeout(Duration.ofSeconds(2)).build());
        factory.afterPropertiesSet();
        try {
            factory.getConnection().stringCommands().set(
                    ("oauth:state:" + state).getBytes(), newStoredValue.getBytes());
        } finally {
            factory.destroy();
        }
    }

    private void stubTokenExchangeSuccess(String code, String accessToken) {
        wireMock.stubFor(post(urlEqualTo("/2/oauth2/token"))
                .withRequestBody(containing("code=" + code))
                .willReturn(okJson("{\"access_token\":\"" + accessToken + "\",\"token_type\":\"bearer\","
                        + "\"expires_in\":7200,\"refresh_token\":\"x-refresh-" + accessToken + "\"}")));
    }

    private void stubTokenExchangeDelayed(String code, int delayMs) {
        wireMock.stubFor(post(urlEqualTo("/2/oauth2/token"))
                .withRequestBody(containing("code=" + code))
                .willReturn(aResponse().withFixedDelay(delayMs)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"irrelevant\",\"token_type\":\"bearer\"}")));
    }

    private void stubUserLookupSuccess(String accessToken, String xUserId, String username) {
        wireMock.stubFor(get(urlEqualTo("/2/users/me"))
                .withHeader("Authorization", equalTo("Bearer " + accessToken))
                .willReturn(okJson("{\"data\":{\"id\":\"" + xUserId + "\",\"username\":\"" + username + "\"}}")));
    }

    private void stubUserLookupDelayed(String accessToken, int delayMs) {
        wireMock.stubFor(get(urlEqualTo("/2/users/me"))
                .withHeader("Authorization", equalTo("Bearer " + accessToken))
                .willReturn(aResponse().withFixedDelay(delayMs)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"data\":{\"id\":\"irrelevant\",\"username\":\"irrelevant\"}}")));
    }

    private int countCommunityManagersByXUserId(String xUserId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT count(*) FROM community_manager WHERE x_user_id = '" + xUserId + "'")) {
            rs.next();
            return rs.getInt(1);
        }
    }

    private int countAllCommunityManagers() throws SQLException {
        try (Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT count(*) FROM community_manager")) {
            rs.next();
            return rs.getInt(1);
        }
    }

    private int countAccountQuotaRowsForXUserId(String xUserId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT count(*) FROM account_quota aq "
                             + "JOIN community_manager cm ON cm.id = aq.cm_id "
                             + "WHERE cm.x_user_id = '" + xUserId + "'")) {
            rs.next();
            return rs.getInt(1);
        }
    }

    private List<String> handlesForXUserId(String xUserId) throws SQLException {
        List<String> handles = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT x_handle FROM community_manager WHERE x_user_id = '" + xUserId + "'")) {
            while (rs.next()) {
                handles.add(rs.getString(1));
            }
        }
        return handles;
    }

    // Failure test 13 (Section 5.13): a callback with no state parameter, or one that doesn't
    // match any Redis entry, is rejected cleanly.
    // Chunk 4 review, item 2: this rejection must also log a WARN tagged reason=missing-state-or-code.
    @Test
    void missingStateOnCallbackIsRejected(CapturedOutput output) throws Exception {
        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appContext.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double before = meterRegistry.counter("giveaway.auth.failure", "reason", "missing-state-or-code").count();

        HttpResponse<String> response = callback("code=some-code");
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(500);
        assertThat(output.getAll())
                .as("the failure-reason log must name the category")
                .contains("reason=missing-state-or-code");
        // Chunk 4 review (final round), item 2: one counter name for every auth failure --
        // giveaway.auth.failure, not a separate giveaway.oauth.failure for this controller.
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "missing-state-or-code").count())
                .isGreaterThan(before);
    }

    // Chunk 4 review, item 2: this rejection must log a WARN tagged
    // reason=unknown-or-replayed-state, and that log must NEVER contain the actual (unknown)
    // state value itself -- only the fixed category.
    @Test
    void unknownStateOnCallbackIsRejected(CapturedOutput output) throws Exception {
        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appContext.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double before = meterRegistry.counter("giveaway.auth.failure", "reason", "unknown-or-replayed-state").count();

        String unknownState = "totally-unknown-state-value-" + UUID.randomUUID();
        HttpResponse<String> response = callback("code=some-code&state=" + unknownState);
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(500);
        assertThat(output.getAll())
                .as("the failure-reason log must name the category")
                .contains("reason=unknown-or-replayed-state");
        assertThat(output.getAll())
                .as("the real (unknown) state value must never appear in any captured log line")
                .doesNotContain(unknownState);
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "unknown-or-replayed-state").count())
                .isGreaterThan(before);
    }

    // Failure test 14 (Section 5.14): state replay -- using a state a second time, after its
    // first legitimate use already consumed and deleted the Redis entry, fails the same way.
    @Test
    void stateReplayIsRejected() throws Exception {
        String xUserId = uniqueNumericXUserId();
        HttpResponse<Void> loginResponse = startLogin();
        String location = loginResponse.headers().firstValue("Location").orElseThrow();
        String state = queryParam(location, "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");

        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupSuccess(accessToken, xUserId, "firstuse");

        HttpResponse<String> first = callback("code=" + code + "&state=" + state, bindingCookie);
        assertThat(first.statusCode()).isBetween(200, 299);

        // Second use of the SAME state: the Redis entry was deleted on first read.
        HttpResponse<String> replay = callback("code=" + code + "&state=" + state, bindingCookie);
        assertThat(replay.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(500);
    }

    // Failure test 15 (Section 5.15): a code_verifier that doesn't match the code_challenge
    // originally sent to X fails the token exchange -- proving this app's own PKCE wiring is
    // correct, not merely trusted to X.
    @Test
    void pkceVerifierMismatchFailsTokenExchange() throws Exception {
        HttpResponse<Void> loginResponse = startLogin();
        String location = loginResponse.headers().firstValue("Location").orElseThrow();
        String state = queryParam(location, "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");
        String originalVerifier = readStoredVerifier(state);
        assertThat(originalVerifier).as("the app must have stored a PKCE verifier for this state").isNotNull();

        String code = "code-" + UUID.randomUUID();
        // Good-match stub: only succeeds if the ORIGINAL verifier is sent (X's real behavior).
        wireMock.stubFor(post(urlEqualTo("/2/oauth2/token"))
                .atPriority(1)
                .withRequestBody(containing("code_verifier=" + originalVerifier))
                .willReturn(okJson("{\"access_token\":\"should-not-be-used\",\"token_type\":\"bearer\"}")));
        // Catch-all: any other verifier -- X's real invalid_grant rejection.
        wireMock.stubFor(post(urlEqualTo("/2/oauth2/token"))
                .atPriority(5)
                .willReturn(aResponse().withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"error\":\"invalid_grant\"}")));

        // Corrupt the stored verifier server-side before the callback uses it.
        overwriteStoredVerifier(state, "deliberately-wrong-verifier-value");

        HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(500);
    }

    // Failure test 16 (Section 5.16): X's own callback error parameter is handled cleanly, not
    // a crash -- e.g. the CM declined authorization on X's own consent screen.
    // Chunk 4 review, item 2: this rejection must log a WARN tagged reason=x-error-param, and
    // never echo X's own raw error text ("access_denied") into the log.
    @Test
    void xsOwnCallbackErrorParameterHandledCleanly(CapturedOutput output) throws Exception {
        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appContext.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double before = meterRegistry.counter("giveaway.auth.failure", "reason", "x-error-param").count();

        HttpResponse<String> response = callback("error=access_denied");
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(500);
        assertThat(response.statusCode()).isNotEqualTo(500);
        assertThat(output.getAll())
                .as("the failure-reason log must name the category")
                .contains("reason=x-error-param");
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "x-error-param").count())
                .isGreaterThan(before);
    }

    // Failure test 17 (Section 5.17), sub-case A: an X timeout during the TOKEN EXCHANGE call
    // leaves no half-created community_manager row.
    // Chunk 4 review, item 2: this rejection must log a WARN tagged reason=x-exchange-failed, and
    // that log must never contain the real code or X access token values.
    @Test
    void timeoutDuringTokenExchangeLeavesNoHalfCreatedCommunityManagerRow(CapturedOutput output) throws Exception {
        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appContext.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double failuresBefore = meterRegistry.counter("giveaway.auth.failure", "reason", "x-exchange-failed").count();

        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");
        String code = "code-" + UUID.randomUUID();
        stubTokenExchangeDelayed(code, 5000); // far past the 2000ms configured timeout

        int before = countAllCommunityManagers();
        HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);

        // FIRST: the app must have actually attempted the token exchange at all -- this is the
        // assertion that fails against the current 501-returning stub, which never calls out to
        // X in the first place, so there is nothing real for the rest of this test to prove yet.
        awaitWireMockRequest(postRequestedFor(urlPathEqualTo("/2/oauth2/token")));

        // THEN: a clean 4xx/5xx-but-not-crashed response shape, not an unhandled exception.
        assertThat(response.statusCode()).isNotEqualTo(500);
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(600);

        // AND: no half-created row.
        assertThat(countAllCommunityManagers())
                .as("no half-created row from a token-exchange timeout")
                .isEqualTo(before);

        assertThat(output.getAll())
                .as("the failure-reason log must name the category")
                .contains("reason=x-exchange-failed");
        assertThat(output.getAll())
                .as("the real code value must never appear in any captured log line")
                .doesNotContain(code);
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "x-exchange-failed").count())
                .isGreaterThan(failuresBefore);
    }

    // Failure test 17 (Section 5.17), sub-case B: an X timeout during the USER LOOKUP call
    // leaves no half-created community_manager row (the token exchange itself succeeded).
    @Test
    void timeoutDuringUserLookupLeavesNoHalfCreatedCommunityManagerRow() throws Exception {
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");
        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupDelayed(accessToken, 5000); // far past the 2000ms configured timeout

        int before = countAllCommunityManagers();
        HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);

        // FIRST: the app must have actually attempted the user lookup (which requires the token
        // exchange to have already succeeded first) -- fails against the current 501-returning
        // stub, which never calls out to X at all.
        awaitWireMockRequest(getRequestedFor(urlPathEqualTo("/2/users/me")));

        assertThat(response.statusCode()).isNotEqualTo(500);
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(600);
        assertThat(countAllCommunityManagers())
                .as("no half-created row from a user-lookup timeout, even though the token "
                        + "exchange itself already succeeded")
                .isEqualTo(before);
    }

    // Chunk 4 review (second round), item 2: a genuine DB failure during the upsert (a locked
    // row blocking past the statement_timeout bound) must fail closed as 503, with an empty
    // generic body and no half-created row -- never a raw 500. The lock is held on a row that
    // ALREADY EXISTS for this x_user_id, so the callback's INSERT ... ON CONFLICT DO UPDATE must
    // wait for it specifically (a fresh x_user_id with no existing row would never need the lock
    // at all).
    @Test
    @org.junit.jupiter.api.Timeout(value = 20, unit = java.util.concurrent.TimeUnit.SECONDS)
    void dbFailureDuringUpsertReturns503AndCreatesNoHalfCreatedRow(CapturedOutput output) throws Exception {
        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appContext.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double failuresBefore = meterRegistry.counter("giveaway.auth.failure", "reason", "db-unavailable").count();

        String xUserId = uniqueNumericXUserId();

        try (Connection setup = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                java.sql.PreparedStatement ps = setup.prepareStatement(
                        "INSERT INTO community_manager (id, x_handle, created_at, x_user_id) VALUES (?,?,?,?)")) {
            ps.setObject(1, UUID.randomUUID());
            ps.setString(2, "lockholder_db_fail");
            ps.setTimestamp(3, java.sql.Timestamp.from(java.time.Instant.now()));
            ps.setString(4, xUserId);
            ps.executeUpdate();
        }

        Connection lockHolder = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        lockHolder.setAutoCommit(false);
        try (java.sql.PreparedStatement ps = lockHolder.prepareStatement(
                "SELECT id FROM community_manager WHERE x_user_id = ? FOR UPDATE")) {
            ps.setString(1, xUserId);
            ps.executeQuery();
        }

        try {
            HttpResponse<Void> loginResponse = startLogin();
            String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
            String bindingCookie = setCookiePair(loginResponse, "oauthBinding");
            String code = "code-" + UUID.randomUUID();
            String accessToken = "access-" + UUID.randomUUID();
            stubTokenExchangeSuccess(code, accessToken);
            stubUserLookupSuccess(accessToken, xUserId, "db_fail_handle");

            int before = countAllCommunityManagers();
            HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);

            assertThat(response.statusCode())
                    .as("a DB failure during the upsert must fail closed as 503, never a raw 500")
                    .isEqualTo(503);
            assertThat(response.body()).isEmpty();
            assertThat(countAllCommunityManagers())
                    .as("no half-created (or half-updated) row from this DB failure")
                    .isEqualTo(before);

            assertThat(output.getAll())
                    .as("the failure-reason log must name the category")
                    .contains("reason=db-unavailable");
            assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "db-unavailable").count())
                    .isGreaterThan(failuresBefore);
        } finally {
            lockHolder.rollback();
            lockHolder.close();
        }
    }

    // Failure test 18 (Section 5.18): two concurrent first-time logins resolving to the SAME
    // x_user_id create exactly one community_manager row, not two.
    @Test
    void concurrentFirstTimeLoginsForSameXUserCreateExactlyOneRow() throws Exception {
        String sharedXUserId = uniqueNumericXUserId();

        HttpResponse<Void> login1 = startLogin();
        String state1 = queryParam(login1.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie1 = setCookiePair(login1, "oauthBinding");
        HttpResponse<Void> login2 = startLogin();
        String state2 = queryParam(login2.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie2 = setCookiePair(login2, "oauthBinding");

        String code1 = "code-1-" + UUID.randomUUID();
        String code2 = "code-2-" + UUID.randomUUID();
        String accessToken1 = "access-1-" + UUID.randomUUID();
        String accessToken2 = "access-2-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code1, accessToken1);
        stubTokenExchangeSuccess(code2, accessToken2);
        stubUserLookupSuccess(accessToken1, sharedXUserId, "doubleclicker");
        stubUserLookupSuccess(accessToken2, sharedXUserId, "doubleclicker");

        CountDownLatch startLatch = new CountDownLatch(2);
        CountDownLatch doneLatch = new CountDownLatch(2);
        AtomicReference<Throwable> unexpected = new AtomicReference<>();
        AtomicReference<Integer> status1 = new AtomicReference<>();
        AtomicReference<Integer> status2 = new AtomicReference<>();

        Runnable call1 = () -> {
            try {
                startLatch.countDown();
                startLatch.await();
                status1.set(callback("code=" + code1 + "&state=" + state1, bindingCookie1).statusCode());
            } catch (Throwable t) {
                unexpected.set(t);
            } finally {
                doneLatch.countDown();
            }
        };
        Runnable call2 = () -> {
            try {
                startLatch.countDown();
                startLatch.await();
                status2.set(callback("code=" + code2 + "&state=" + state2, bindingCookie2).statusCode());
            } catch (Throwable t) {
                unexpected.set(t);
            } finally {
                doneLatch.countDown();
            }
        };

        new Thread(call1).start();
        new Thread(call2).start();
        doneLatch.await();

        assertThat(unexpected.get()).as("no unexpected exception from either concurrent login").isNull();
        assertThat(countCommunityManagersByXUserId(sharedXUserId))
                .as("exactly one community_manager row for this x_user_id, not two")
                .isEqualTo(1);
        // The unique constraint on x_user_id alone already forces the row count above to 1 even
        // under a select-then-insert implementation -- it just makes the LOSING request blow up
        // with a constraint-violation exception (500) instead of resolving gracefully via
        // ON CONFLICT. Both calls succeeding cleanly is the property that actually distinguishes
        // a real upsert from a race-prone select-then-insert.
        assertThat(status1.get())
                .as("neither concurrent login may fail with an unhandled exception (select-then-insert "
                        + "would surface the loser's unique-constraint violation as a 500)")
                .isBetween(200, 299);
        assertThat(status2.get())
                .as("neither concurrent login may fail with an unhandled exception (select-then-insert "
                        + "would surface the loser's unique-constraint violation as a 500)")
                .isBetween(200, 299);
    }

    // Failure test 19 (Section 5.19): a handle rename updates the SAME account, not a new one.
    @Test
    void handleRenameUpdatesSameAccountNotANewOne() throws Exception {
        String xUserId = uniqueNumericXUserId();

        HttpResponse<Void> login1 = startLogin();
        String state1 = queryParam(login1.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie1 = setCookiePair(login1, "oauthBinding");
        String code1 = "code-1-" + UUID.randomUUID();
        String accessToken1 = "access-1-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code1, accessToken1);
        stubUserLookupSuccess(accessToken1, xUserId, "old_handle");
        HttpResponse<String> first = callback("code=" + code1 + "&state=" + state1, bindingCookie1);
        assertThat(first.statusCode()).isBetween(200, 299);
        assertThat(handlesForXUserId(xUserId)).containsExactly("old_handle");

        HttpResponse<Void> login2 = startLogin();
        String state2 = queryParam(login2.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie2 = setCookiePair(login2, "oauthBinding");
        String code2 = "code-2-" + UUID.randomUUID();
        String accessToken2 = "access-2-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code2, accessToken2);
        stubUserLookupSuccess(accessToken2, xUserId, "new_handle2");
        HttpResponse<String> second = callback("code=" + code2 + "&state=" + state2, bindingCookie2);
        assertThat(second.statusCode()).isBetween(200, 299);

        assertThat(countCommunityManagersByXUserId(xUserId))
                .as("a rename must update the same row, not create a second one")
                .isEqualTo(1);
        assertThat(handlesForXUserId(xUserId))
                .as("x_handle must be refreshed to the new value on every login")
                .containsExactly("new_handle2");
    }

    // Failure test 20 (Section 5.20): X's own tokens are discarded, not stored -- not in the
    // database, not in Redis, and not in any captured log line.
    @Test
    void xsOwnTokensAreDiscardedNotStored(CapturedOutput output) throws Exception {
        String xUserId = uniqueNumericXUserId();
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");
        String code = "code-" + UUID.randomUUID();
        String xAccessToken = "x-access-token-very-secret-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, xAccessToken);
        stubUserLookupSuccess(xAccessToken, xUserId, "discard_me");

        HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);
        assertThat(response.statusCode()).isBetween(200, 299);

        assertThat(output.getAll())
                .as("X's own access token must never appear in any captured log line")
                .doesNotContain(xAccessToken);

        try (Connection conn = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
            assertThat(tableContainsLiteral(conn, "community_manager", xAccessToken)).isFalse();
            assertThat(tableContainsLiteral(conn, "refresh_token", xAccessToken)).isFalse();
        }

        RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration(
                REDIS.getHost(), REDIS.getMappedPort(6379));
        redisConfig.setPassword(REDIS_PASSWORD);
        LettuceConnectionFactory factory = new LettuceConnectionFactory(redisConfig,
                LettuceClientConfiguration.builder().commandTimeout(Duration.ofSeconds(2)).build());
        factory.afterPropertiesSet();
        try {
            var keys = factory.getConnection().keyCommands().keys("*".getBytes());
            assertThat(keys).isNotNull();
            for (byte[] key : keys) {
                byte[] value = factory.getConnection().stringCommands().get(key);
                if (value != null) {
                    assertThat(new String(value)).doesNotContain(xAccessToken);
                }
            }
        } finally {
            factory.destroy();
        }
    }

    private boolean tableContainsLiteral(Connection conn, String table, String literal) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet columns = st.executeQuery(
                     "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '"
                             + table + "'")) {
            List<String> textColumns = new ArrayList<>();
            while (columns.next()) {
                String type = columns.getString("data_type");
                if (type.contains("char") || type.contains("text")) {
                    textColumns.add(columns.getString("column_name"));
                }
            }
            for (String column : textColumns) {
                try (Statement check = conn.createStatement();
                     ResultSet rs = check.executeQuery(
                             "SELECT count(*) FROM " + table + " WHERE " + column + " = '" + literal + "'")) {
                    rs.next();
                    if (rs.getInt(1) > 0) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // New RED test (f): the token-exchange request this app actually sends to X must include the
    // PKCE code_verifier it stored for this state -- not just "some verifier the stub happens to
    // accept." Isolates the mutation "verifier left out of the token exchange" from "wrong
    // verifier sent" (pkceVerifierMismatchFailsTokenExchange, above, can't tell those two apart by
    // itself: both end up hitting the catch-all 400 stub there). FAILS TODAY: the stub never
    // calls X at all, so no request to assert against exists yet.
    @Test
    void tokenExchangeRequestIncludesTheStoredPkceVerifier() throws Exception {
        String xUserId = uniqueNumericXUserId();
        HttpResponse<Void> loginResponse = startLogin();
        String location = loginResponse.headers().firstValue("Location").orElseThrow();
        String state = queryParam(location, "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");
        String verifier = readStoredVerifier(state);
        assertThat(verifier).isNotNull();

        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupSuccess(accessToken, xUserId, "verifier_chk");

        HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);
        assertThat(response.statusCode()).isBetween(200, 299);

        wireMock.verify(postRequestedFor(urlEqualTo("/2/oauth2/token"))
                .withRequestBody(containing("code_verifier=" + verifier)));
    }

    // New RED test (g) -- plan doc Section 0 / PRD Section 3 ("CommunityManager 1 owns 1
    // AccountQuota"): a brand-new CM created by this login flow gets exactly one account_quota
    // row, not zero. FAILS TODAY: the stub never creates a community_manager row at all, so
    // there is nothing for an account_quota row to even reference.
    @Test
    void newCommunityManagerGetsExactlyOneAccountQuotaRow() throws Exception {
        String xUserId = uniqueNumericXUserId();
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");
        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupSuccess(accessToken, xUserId, "quota_chk");

        HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);
        assertThat(response.statusCode()).isBetween(200, 299);

        assertThat(countAccountQuotaRowsForXUserId(xUserId))
                .as("a brand-new community_manager row must get exactly one account_quota row, "
                        + "created in the same transaction (PRD: CommunityManager 1 owns 1 AccountQuota)")
                .isEqualTo(1);
    }

    // Happy path (Tests summary): OAuth login against mocked X endpoints -- callback upserts
    // the community_manager row and sets session cookies.
    // Also covers failure test 8 (Section 5.8): the real Set-Cookie headers from this real
    // response carry HttpOnly, Secure, and SameSite=Strict on BOTH the access and refresh
    // cookies.
    @Test
    void happyPathLoginCreatesRowAndSetsSessionCookiesWithExpectedFlags() throws Exception {
        String xUserId = uniqueNumericXUserId();
        HttpResponse<Void> loginResponse = startLogin();
        assertThat(loginResponse.statusCode()).isEqualTo(302);
        String location = loginResponse.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith("https://x.com/i/oauth2/authorize");
        String state = queryParam(location, "state");
        assertThat(state).isNotNull();
        assertThat(queryParam(location, "code_challenge")).isNotNull();
        assertThat(queryParam(location, "code_challenge_method")).isEqualTo("S256");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");
        assertThat(bindingCookie).as("the login response must set the oauthBinding cookie").isNotNull();

        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupSuccess(accessToken, xUserId, "happy_handle");

        HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);
        assertThat(response.statusCode()).isBetween(200, 299);

        List<String> setCookies = response.headers().allValues("Set-Cookie");
        assertThat(setCookies).hasSizeGreaterThanOrEqualTo(2);

        boolean anyAccessCookie = false;
        boolean anyRefreshCookie = false;
        for (String cookie : setCookies) {
            if (cookie.toLowerCase().startsWith("accesstoken=") || cookie.toLowerCase().startsWith("refreshtoken=")) {
                assertThat(cookie).contains("HttpOnly").contains("Secure").contains("SameSite=Strict");
            }
            if (cookie.toLowerCase().startsWith("accesstoken=")) {
                anyAccessCookie = true;
            }
            if (cookie.toLowerCase().startsWith("refreshtoken=")) {
                anyRefreshCookie = true;
            }
        }
        assertThat(anyAccessCookie).as("an access-token cookie must be set").isTrue();
        assertThat(anyRefreshCookie).as("a refresh-token cookie must be set").isTrue();

        // The binding cookie must be cleared on success too (item 1: "clear the cookie on every outcome").
        String clearedBindingCookie = fullSetCookieHeader(response, "oauthBinding");
        assertThat(clearedBindingCookie).as("oauthBinding must be cleared on success").isNotNull();
        assertThat(clearedBindingCookie).containsIgnoringCase("Max-Age=0");

        assertThat(countCommunityManagersByXUserId(xUserId)).isEqualTo(1);
    }

    // Failure test 8 (Section 5.8), isolated: cookie flags are asserted directly against a real
    // response, not assumed from code review. Deliberately does NOT depend on the PKCE
    // code_challenge assertions in the happy-path test above -- this test's only job is to prove
    // the Set-Cookie headers are both present (first, must fail against the current 501-returning
    // stub, which sets no cookies at all) and correctly flagged (HttpOnly, Secure,
    // SameSite=Strict, Path, Max-Age), for BOTH the access and refresh cookies.
    @Test
    void cookieFlagsAssertedDirectly() throws Exception {
        String xUserId = uniqueNumericXUserId();
        HttpResponse<Void> loginResponse = startLogin();
        String location = loginResponse.headers().firstValue("Location").orElseThrow();
        String state = queryParam(location, "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");

        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupSuccess(accessToken, xUserId, "cookie_flag");

        HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);

        // FIRST: the cookies must actually exist at all. This is the assertion that fails
        // meaningfully against the current stub (which returns 501 with no Set-Cookie headers) --
        // everything below this line only runs once this passes for real.
        List<String> setCookies = response.headers().allValues("Set-Cookie");
        assertThat(setCookies)
                .as("both an access-token and a refresh-token Set-Cookie header must be present")
                .hasSizeGreaterThanOrEqualTo(2);

        String accessCookie = setCookies.stream()
                .filter(c -> c.toLowerCase().startsWith("accesstoken="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no accessToken Set-Cookie header found"));
        String refreshCookie = setCookies.stream()
                .filter(c -> c.toLowerCase().startsWith("refreshtoken="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no refreshToken Set-Cookie header found"));

        // THEN: flags common to both cookies.
        for (String cookie : List.of(accessCookie, refreshCookie)) {
            assertThat(cookie).contains("HttpOnly");
            assertThat(cookie).contains("Secure");
            assertThat(cookie).contains("SameSite=Strict");
            assertThat(cookie).contains("Max-Age=");
        }

        // Chunk 4 review, item 3: the refresh cookie is scoped to /auth/refresh specifically
        // (not every endpoint), since it's the only place this app will ever need to read it --
        // the access cookie stays scoped to "/" since every authenticated endpoint reads it.
        assertThat(pathOf(accessCookie)).as("access cookie Path").isEqualTo("/");
        assertThat(pathOf(refreshCookie)).as("refresh cookie Path").isEqualTo("/auth/refresh");

        // Access cookie Max-Age matches the 15-minute access-token lifetime; refresh cookie
        // Max-Age matches the 7-day refresh-token lifetime (Section 3).
        assertThat(maxAgeOf(accessCookie)).isEqualTo(Duration.ofMinutes(15).toSeconds());
        assertThat(maxAgeOf(refreshCookie)).isEqualTo(Duration.ofDays(7).toSeconds());
    }

    private static String pathOf(String setCookieHeader) {
        for (String part : setCookieHeader.split(";")) {
            String trimmed = part.trim();
            if (trimmed.toLowerCase().startsWith("path=")) {
                return trimmed.substring("path=".length());
            }
        }
        throw new AssertionError("no Path attribute found in: " + setCookieHeader);
    }

    private static long maxAgeOf(String setCookieHeader) {
        for (String part : setCookieHeader.split(";")) {
            String trimmed = part.trim();
            if (trimmed.toLowerCase().startsWith("max-age=")) {
                return Long.parseLong(trimmed.substring("max-age=".length()));
            }
        }
        throw new AssertionError("no Max-Age attribute found in: " + setCookieHeader);
    }

    /** Raw Redis TTL (seconds), via the same Lettuce pattern used elsewhere in this file. */
    private Long ttlOf(String key) {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        config.setPassword(REDIS_PASSWORD);
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, LettuceClientConfiguration.builder()
                .commandTimeout(Duration.ofSeconds(2)).build());
        factory.afterPropertiesSet();
        try {
            return factory.getConnection().keyCommands().ttl(key.getBytes());
        } finally {
            factory.destroy();
        }
    }

    /**
     * Sends a raw HTTP/1.1 GET /auth/login over a plain socket with a forged Host header, since
     * java.net.http.HttpClient refuses to let a caller set the restricted "Host" header at all.
     * Returns the Location header's value.
     */
    private String sendRawRequestWithForgedHost(String forgedHost) throws Exception {
        try (java.net.Socket socket = new java.net.Socket("localhost", appPort)) {
            socket.setSoTimeout(5000);
            String request = "GET /auth/login HTTP/1.1\r\n"
                    + "Host: " + forgedHost + "\r\n"
                    + "Connection: close\r\n"
                    + "\r\n";
            socket.getOutputStream().write(request.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();

            StringBuilder responseText = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(socket.getInputStream(), java.nio.charset.StandardCharsets.US_ASCII))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    responseText.append(line).append('\n');
                }
            }
            for (String line : responseText.toString().split("\n")) {
                if (line.toLowerCase().startsWith("location:")) {
                    return line.substring(line.indexOf(':') + 1).trim();
                }
            }
            throw new AssertionError("no Location header found in raw response:\n" + responseText);
        }
    }

    // New RED test (a) -- plan doc Section 0: "The redirect URI sent to X comes from config
    // (app.x-oauth.redirect-uri, bound from X_OAUTH_REDIRECT_URI), never built from the inbound
    // request's Host header." Two /auth/login calls, one with a forged Host header, must
    // produce byte-identical redirect_uri values, equal to the configured value -- never built
    // from the forged header. FAILS TODAY: the stub never includes a redirect_uri param at all.
    @Test
    void loginRedirectUriAlwaysComesFromConfigNeverFromHostHeader() throws Exception {
        HttpRequest normalRequest = HttpRequest.newBuilder()
                .uri(URI.create(baseUri() + "/auth/login"))
                .GET()
                .build();
        HttpResponse<Void> normalResponse = HTTP.send(normalRequest, HttpResponse.BodyHandlers.discarding());
        String normalLocation = normalResponse.headers().firstValue("Location").orElseThrow();

        // java.net.http.HttpClient refuses to let callers set the restricted "Host" header
        // directly (it's managed by the client itself), so a forged Host header has to be sent
        // over a raw socket instead -- this is still a real HTTP/1.1 request hitting the real,
        // running application, not a mock.
        String forgedLocation = sendRawRequestWithForgedHost("evil.example.com");

        String normalRedirectUri = queryParam(normalLocation, "redirect_uri");
        String forgedRedirectUri = queryParam(forgedLocation, "redirect_uri");

        assertThat(normalRedirectUri)
                .as("redirect_uri must be present and must equal the configured app.x-oauth.redirect-uri value")
                .isEqualTo("http://localhost/auth/callback");
        assertThat(forgedRedirectUri)
                .as("redirect_uri must be present and must equal the configured value even with a forged Host header")
                .isEqualTo("http://localhost/auth/callback");
        assertThat(forgedRedirectUri)
                .as("redirect_uri must never be built from the forged Host header")
                .doesNotContain("evil.example.com");
        assertThat(normalRedirectUri)
                .as("redirect_uri must be byte-identical regardless of the inbound Host header")
                .isEqualTo(forgedRedirectUri);
    }

    // New RED test (b) -- plan doc Section 0: the redirect to X's authorize endpoint must carry
    // response_type=code, the configured client_id, scope "users.read tweet.read",
    // code_challenge_method=S256, a state, and a code_challenge. Each asserted independently so a
    // future failure names exactly which one broke. FAILS TODAY: only "state" exists in the
    // stub's redirect; the other five are entirely absent.
    @Test
    void loginRedirectCarriesAllRequiredAuthorizeParameters() throws Exception {
        HttpResponse<Void> loginResponse = startLogin();
        String location = loginResponse.headers().firstValue("Location").orElseThrow();

        assertThat(queryParam(location, "response_type"))
                .as("response_type must be exactly 'code'")
                .isEqualTo("code");
        assertThat(queryParam(location, "client_id"))
                .as("client_id must equal the configured app.x-oauth.client-id value")
                .isEqualTo("test-client-id");
        assertThat(queryParam(location, "scope"))
                .as("scope must be exactly 'users.read tweet.read' (Section 0)")
                .isEqualTo("users.read tweet.read");
        assertThat(queryParam(location, "code_challenge_method"))
                .as("code_challenge_method must be exactly 'S256'")
                .isEqualTo("S256");
        assertThat(queryParam(location, "state"))
                .as("state must be present")
                .isNotNull();
        assertThat(queryParam(location, "code_challenge"))
                .as("code_challenge must be present")
                .isNotNull();
    }

    // New RED test (c) -- plan doc Section 0: the PKCE code_verifier never appears in the URL,
    // the HTTP response, or any captured log line; it is instead stored server-side in Redis
    // under oauth:state:{state}. FAILS TODAY: the stub never writes anything to Redis at all, so
    // no value is ever stored under this key.
    @Test
    void pkceVerifierNeverLeaksAndIsStoredInRedis(CapturedOutput output) throws Exception {
        HttpResponse<Void> loginResponse = startLogin();
        String location = loginResponse.headers().firstValue("Location").orElseThrow();
        String state = queryParam(location, "state");
        assertThat(state).as("a state value must be present in the redirect").isNotNull();

        String storedVerifier = readStoredVerifier(state);
        assertThat(storedVerifier)
                .as("a PKCE code_verifier must be stored server-side in Redis under oauth:state:{state}")
                .isNotNull();
        assertThat(storedVerifier.length())
                .as("the stored verifier must be a plausible PKCE verifier length (RFC 7636: 43-128 chars)")
                .isGreaterThanOrEqualTo(43);

        assertThat(location)
                .as("the PKCE verifier must never appear in the Location header itself")
                .doesNotContain(storedVerifier);
        assertThat(output.getAll())
                .as("the PKCE verifier must never appear in any captured log line")
                .doesNotContain(storedVerifier);
    }

    // New RED test (d) -- plan doc Section 0 / CLAUDE.md: state must carry at least 128 bits of
    // entropy and be unique across many calls. A bare UUID.randomUUID() (today's stub) carries
    // only 122 bits of entropy per RFC 4122 (6 fixed version/variant bits out of 128 total), which
    // is strictly LESS than 128 -- this test isolates that entropy shortfall as the failure, not
    // uniqueness (which a random UUID would actually satisfy).
    @Test
    void stateHasAtLeast128BitsOfEntropyAndIsUniqueAcross1000Calls() throws Exception {
        java.util.Set<String> states = new java.util.HashSet<>();
        for (int i = 0; i < 1000; i++) {
            HttpResponse<Void> response = startLogin();
            String location = response.headers().firstValue("Location").orElseThrow();
            String state = queryParam(location, "state");
            assertThat(state).isNotNull();
            states.add(state);
        }

        assertThat(states)
                .as("all 1000 state values must be distinct")
                .hasSize(1000);

        for (String state : states) {
            // Hex-encoded: 1 char = 4 bits, so >128 bits requires > 32 chars (strictly more than
            // 122 bits' worth, which bare UUID.toString() -- 36 chars incl. 4 dashes, 32 hex
            // digits -- fails). Base64url: 1 char ~= 6 bits, so >128 bits requires > 22 chars.
            // Either way, require strictly more than ceil(122/4)=31 hex-equivalent chars' worth;
            // concretely: more than 32 raw hex characters once dashes are stripped, which a plain
            // UUID (exactly 32 hex chars = 128 "nominal" bits but only 122 actual entropy bits,
            // since 6 bits are fixed version/variant) must fail.
            String hexOnly = state.replace("-", "");
            boolean looksHex = hexOnly.chars().allMatch(c -> Character.digit(c, 16) >= 0);
            if (looksHex) {
                assertThat(hexOnly.length())
                        .as("hex-encoded state must be at least 33 chars (>128 bits actual entropy, "
                                + "strictly more than a bare UUID's 122 bits) for state=" + state)
                        .isGreaterThan(32);
            } else {
                assertThat(state.length())
                        .as("base64url-encoded state must be at least 23 chars (>128 bits) for state=" + state)
                        .isGreaterThan(22);
            }
        }
    }

    // Chunk 4 review, item 5: the plan doc states the OAuth state TTL is exactly 5 minutes
    // (corrected from an earlier, stale "10 minutes" in the doc that never matched
    // AuthBeansConfig's real Duration.ofMinutes(5)) -- this test now asserts the exact value,
    // not just an upper ceiling that would pass regardless of which of the two was ever right.
    @Test
    void oauthStateKeyHasExactlyFiveMinuteTtl() throws Exception {
        HttpResponse<Void> loginResponse = startLogin();
        String location = loginResponse.headers().firstValue("Location").orElseThrow();
        String state = queryParam(location, "state");
        assertThat(state).isNotNull();

        Long ttlSeconds = ttlOf("oauth:state:" + state);

        assertThat(ttlSeconds)
                .as("oauth:state:{state} must exist with a TTL of EXACTLY 5 minutes (a Lettuce "
                        + "ttl() of -2 means the key does not exist at all, -1 means it exists "
                        + "with no expiry -- either is a failure here, and so is any other "
                        + "duration, per the plan doc's now-corrected '5 minutes' statement)")
                .isNotNull()
                .isEqualTo(Duration.ofMinutes(5).toSeconds());
    }

    // Chunk 4 review, item 1 (login CSRF): /auth/login must set a browser-bound anti-CSRF
    // cookie, SameSite=Lax (NOT Strict -- a Lax cookie is the only kind that survives X's
    // cross-site top-level redirect back into /auth/callback), scoped to /auth, with a 5-minute
    // Max-Age. FAILS TODAY: no such cookie exists at all.
    @Test
    void loginSetsOauthBindingCookieWithLaxFlags() throws Exception {
        HttpResponse<Void> loginResponse = startLogin();
        String bindingCookieHeader = fullSetCookieHeader(loginResponse, "oauthBinding");

        assertThat(bindingCookieHeader).as("oauthBinding Set-Cookie header must be present").isNotNull();
        assertThat(bindingCookieHeader).contains("HttpOnly");
        assertThat(bindingCookieHeader).contains("Secure");
        assertThat(bindingCookieHeader)
                .as("the binding cookie must be SameSite=Lax, not Strict -- Strict would never "
                        + "arrive on X's cross-site redirect into /auth/callback")
                .contains("SameSite=Lax")
                .doesNotContain("SameSite=Strict");
        assertThat(bindingCookieHeader).contains("Path=/auth");
        assertThat(maxAgeOf(bindingCookieHeader)).isEqualTo(300L);
    }

    // Chunk 4 review, item 1: a callback with a genuinely valid state and code, but no
    // oauthBinding cookie at all, is rejected -- and rejected BEFORE either X call, so no
    // half-created row and no X traffic. FAILS TODAY: no binding check exists at all.
    // Chunk 4 review, item 2: this rejection must also log a WARN tagged
    // reason=missing-or-mismatched-binding-cookie.
    @Test
    void callbackWithValidStateAndCodeButMissingBindingCookieIsRejected(CapturedOutput output) throws Exception {
        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appContext.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double failuresBefore = meterRegistry
                .counter("giveaway.auth.failure", "reason", "missing-or-mismatched-binding-cookie").count();

        String xUserId = uniqueNumericXUserId();
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupSuccess(accessToken, xUserId, "no_cookie_h");

        HttpResponse<String> response = callback("code=" + code + "&state=" + state); // no Cookie header at all

        assertThat(response.statusCode())
                .as("missing binding cookie must be rejected with the same generic 400")
                .isEqualTo(400);
        assertThat(response.body()).as("no echoed detail in the body").isEmpty();
        assertThat(countCommunityManagersByXUserId(xUserId))
                .as("no row may be created when the binding cookie is missing")
                .isEqualTo(0);
        wireMock.verify(0, postRequestedFor(urlPathEqualTo("/2/oauth2/token")));

        String clearedBindingCookie = fullSetCookieHeader(response, "oauthBinding");
        assertThat(clearedBindingCookie).as("oauthBinding must be cleared even on this failure").isNotNull();
        assertThat(clearedBindingCookie).containsIgnoringCase("Max-Age=0");

        assertThat(output.getAll())
                .as("the failure-reason log must name the category")
                .contains("reason=missing-or-mismatched-binding-cookie");
        assertThat(meterRegistry
                .counter("giveaway.auth.failure", "reason", "missing-or-mismatched-binding-cookie").count())
                .isGreaterThan(failuresBefore);
    }

    // Chunk 4 review, item 1: a callback with the WRONG oauthBinding cookie is rejected, and the
    // state is burned by that rejected attempt -- a second attempt with the CORRECT cookie (and
    // the same still-valid code/state) also fails, since the state was already consumed by the
    // GETDEL on the first (wrong-cookie) attempt. FAILS TODAY: no binding check exists at all, so
    // the first call would succeed outright.
    @Test
    void callbackWithWrongBindingCookieBurnsStateAndRejects() throws Exception {
        String xUserId = uniqueNumericXUserId();
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String correctBindingCookie = setCookiePair(loginResponse, "oauthBinding");
        String wrongBindingCookie = "oauthBinding=" + UUID.randomUUID() + UUID.randomUUID();

        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupSuccess(accessToken, xUserId, "wrong_cookie");

        HttpResponse<String> firstAttempt = callback("code=" + code + "&state=" + state, wrongBindingCookie);
        assertThat(firstAttempt.statusCode())
                .as("wrong binding cookie must be rejected with the same generic 400")
                .isEqualTo(400);
        assertThat(countCommunityManagersByXUserId(xUserId)).isEqualTo(0);

        // Second attempt, correct cookie this time -- the state was already burned above.
        HttpResponse<String> secondAttempt = callback("code=" + code + "&state=" + state, correctBindingCookie);
        assertThat(secondAttempt.statusCode())
                .as("the state was already consumed by the first (wrong-cookie) attempt's GETDEL")
                .isEqualTo(400);
        assertThat(countCommunityManagersByXUserId(xUserId)).isEqualTo(0);
    }

    // Chunk 4 review, item 4: an oversized state parameter (>128 chars) is rejected with the
    // generic 400 before X is ever touched. FAILS TODAY: no length bound exists, so an oversized
    // (but Redis-unknown) state just falls through to the ordinary "unknown state" 400 -- this
    // test's real job is the wireMock.verify(0, ...) below, proving X was never reached, which an
    // unbounded implementation would still happen to satisfy by accident (unknown state already
    // short-circuits before X) -- kept anyway as the direct, named proof the instruction asked
    // for, with the oversized-code test below carrying the ordering proof that actually
    // distinguishes "checked early" from "checked late / not at all".
    @Test
    void oversizedStateIsRejectedBeforeTouchingX() throws Exception {
        String oversizedState = "a".repeat(129);
        String code = "code-" + UUID.randomUUID();

        HttpResponse<String> response = callback("code=" + code + "&state=" + oversizedState);

        assertThat(response.statusCode()).isEqualTo(400);
        wireMock.verify(0, postRequestedFor(urlPathEqualTo("/2/oauth2/token")));
        wireMock.verify(0, getRequestedFor(urlPathEqualTo("/2/users/me")));
    }

    // Chunk 4 review, item 4: an oversized code parameter (>512 chars) is rejected BEFORE the
    // state is consumed -- proven by reusing the SAME real state afterward with a normal-length
    // code and watching it still succeed. If the length bound were missing, or checked only after
    // the GETDEL, the first (oversized-code) attempt would have already burned the state, and this
    // second, otherwise-legitimate attempt would fail as "unknown/replayed state" instead.
    // Chunk 4 review, item 2: the oversized-code rejection must log a WARN tagged
    // reason=state-or-code-too-long, and that log must never contain the oversized code itself.
    @Test
    void oversizedCodeIsRejectedWithoutBurningTheState(CapturedOutput output) throws Exception {
        io.micrometer.core.instrument.MeterRegistry meterRegistry =
                appContext.getBean(io.micrometer.core.instrument.MeterRegistry.class);
        double failuresBefore = meterRegistry.counter("giveaway.auth.failure", "reason", "state-or-code-too-long").count();

        String xUserId = uniqueNumericXUserId();
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");

        String oversizedCode = "c".repeat(513);
        HttpResponse<String> firstAttempt = callback("code=" + oversizedCode + "&state=" + state, bindingCookie);
        assertThat(firstAttempt.statusCode()).isEqualTo(400);
        wireMock.verify(0, postRequestedFor(urlPathEqualTo("/2/oauth2/token")));
        assertThat(output.getAll())
                .as("the failure-reason log must name the category")
                .contains("reason=state-or-code-too-long");
        assertThat(output.getAll())
                .as("the oversized code value must never appear in any captured log line")
                .doesNotContain(oversizedCode);
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "state-or-code-too-long").count())
                .isGreaterThan(failuresBefore);

        String normalCode = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(normalCode, accessToken);
        stubUserLookupSuccess(accessToken, xUserId, "bounds_chk");

        HttpResponse<String> secondAttempt = callback("code=" + normalCode + "&state=" + state, bindingCookie);
        assertThat(secondAttempt.statusCode())
                .as("the state must still be usable -- the oversized code must have been rejected "
                        + "BEFORE the GETDEL, never burning the state")
                .isBetween(200, 299);
    }

    // Chunk 4 review, item 4: X's own user-lookup response is validated, not trusted blindly.
    // An id that isn't a plausible X numeric id (^[0-9]{1,20}$) is treated as a lookup failure --
    // same clean 400, no half-created row. FAILS TODAY: no validation exists, so any string would
    // be written straight into x_user_id.
    @Test
    void userLookupResponseWithInvalidIdFailsCleanly() throws Exception {
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");
        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        wireMock.stubFor(get(urlEqualTo("/2/users/me"))
                .withHeader("Authorization", equalTo("Bearer " + accessToken))
                .willReturn(okJson("{\"data\":{\"id\":\"not-a-valid-id!!\",\"username\":\"validhandle\"}}")));

        int before = countAllCommunityManagers();
        HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(countAllCommunityManagers()).isEqualTo(before);
    }

    // Chunk 4 review, item 4: an invalid username (outside ^[A-Za-z0-9_]{1,15}$) is treated the
    // same way -- a clean lookup failure, no row created.
    @Test
    void userLookupResponseWithInvalidUsernameFailsCleanly() throws Exception {
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String bindingCookie = setCookiePair(loginResponse, "oauthBinding");
        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        wireMock.stubFor(get(urlEqualTo("/2/users/me"))
                .withHeader("Authorization", equalTo("Bearer " + accessToken))
                .willReturn(okJson("{\"data\":{\"id\":\"1234567890\",\"username\":\"has a space\"}}")));

        int before = countAllCommunityManagers();
        HttpResponse<String> response = callback("code=" + code + "&state=" + state, bindingCookie);

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(countAllCommunityManagers()).isEqualTo(before);
    }
}
