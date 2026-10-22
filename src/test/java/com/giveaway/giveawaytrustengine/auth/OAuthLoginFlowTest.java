package com.giveaway.giveawaytrustengine.auth;

import com.github.tomakehurst.wiremock.WireMockServer;
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
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
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

    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse(TestImages.REDIS))
            .withExposedPorts(6379);

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
                        "--spring.data.redis.host=" + REDIS.getHost(),
                        "--spring.data.redis.port=" + REDIS.getMappedPort(6379),
                        "--app.environment=DEV",
                        "--app.bachs.sandbox-base-url=https://sandbox-api.bachs.io",
                        "--app.bachs.live-base-url=https://api.bachs.io",
                        "--app.bachs.base-url=https://sandbox-api.bachs.io",
                        "--app.jwt.signing-key=01234567890123456789012345678901",
                        "--app.x-oauth.client-id=test-client-id",
                        "--app.x-oauth.client-secret=test-client-secret",
                        "--app.x-oauth.redirect-uri=http://localhost/auth/callback",
                        "--app.x-oauth.authorize-url=https://x.com/i/oauth2/authorize",
                        "--app.x-oauth.token-url=" + wireMock.baseUrl() + "/2/oauth2/token",
                        "--app.x-oauth.user-lookup-url=" + wireMock.baseUrl() + "/2/users/me",
                        "--app.x-oauth.connect-timeout=500ms",
                        "--app.x-oauth.request-timeout=500ms");

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
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUri() + "/auth/callback?" + query))
                .GET()
                .build();
        return HTTP.send(request, HttpResponse.BodyHandlers.ofString());
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

    /** Reads the single-use PKCE verifier this app stored server-side in Redis for a state. */
    private String readStoredVerifier(String state) {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
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

    private void overwriteStoredVerifier(String state, String newVerifier) {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        LettuceConnectionFactory factory = new LettuceConnectionFactory(config, LettuceClientConfiguration.builder()
                .commandTimeout(Duration.ofSeconds(2)).build());
        factory.afterPropertiesSet();
        try {
            factory.getConnection().stringCommands().set(
                    ("oauth:state:" + state).getBytes(), newVerifier.getBytes());
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
    @Test
    void missingStateOnCallbackIsRejected() throws Exception {
        HttpResponse<String> response = callback("code=some-code");
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(500);
    }

    @Test
    void unknownStateOnCallbackIsRejected() throws Exception {
        HttpResponse<String> response = callback("code=some-code&state=totally-unknown-state-value");
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(500);
    }

    // Failure test 14 (Section 5.14): state replay -- using a state a second time, after its
    // first legitimate use already consumed and deleted the Redis entry, fails the same way.
    @Test
    void stateReplayIsRejected() throws Exception {
        String xUserId = "x-user-" + UUID.randomUUID();
        HttpResponse<Void> loginResponse = startLogin();
        String location = loginResponse.headers().firstValue("Location").orElseThrow();
        String state = queryParam(location, "state");

        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupSuccess(accessToken, xUserId, "firstuse");

        HttpResponse<String> first = callback("code=" + code + "&state=" + state);
        assertThat(first.statusCode()).isBetween(200, 299);

        // Second use of the SAME state: the Redis entry was deleted on first read.
        HttpResponse<String> replay = callback("code=" + code + "&state=" + state);
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

        HttpResponse<String> response = callback("code=" + code + "&state=" + state);
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(500);
    }

    // Failure test 16 (Section 5.16): X's own callback error parameter is handled cleanly, not
    // a crash -- e.g. the CM declined authorization on X's own consent screen.
    @Test
    void xsOwnCallbackErrorParameterHandledCleanly() throws Exception {
        HttpResponse<String> response = callback("error=access_denied");
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(500);
        assertThat(response.statusCode()).isNotEqualTo(500);
    }

    // Failure test 17 (Section 5.17), sub-case A: an X timeout during the TOKEN EXCHANGE call
    // leaves no half-created community_manager row.
    @Test
    void timeoutDuringTokenExchangeLeavesNoHalfCreatedCommunityManagerRow() throws Exception {
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String code = "code-" + UUID.randomUUID();
        stubTokenExchangeDelayed(code, 3000); // far past the 500ms configured timeout

        int before = countAllCommunityManagers();
        HttpResponse<String> response = callback("code=" + code + "&state=" + state);

        assertThat(response.statusCode()).isNotEqualTo(500);
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(600);
        assertThat(countAllCommunityManagers())
                .as("no half-created row from a token-exchange timeout")
                .isEqualTo(before);
    }

    // Failure test 17 (Section 5.17), sub-case B: an X timeout during the USER LOOKUP call
    // leaves no half-created community_manager row (the token exchange itself succeeded).
    @Test
    void timeoutDuringUserLookupLeavesNoHalfCreatedCommunityManagerRow() throws Exception {
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupDelayed(accessToken, 3000); // far past the 500ms configured timeout

        int before = countAllCommunityManagers();
        HttpResponse<String> response = callback("code=" + code + "&state=" + state);

        assertThat(response.statusCode()).isNotEqualTo(500);
        assertThat(response.statusCode()).isGreaterThanOrEqualTo(400).isLessThan(600);
        assertThat(countAllCommunityManagers())
                .as("no half-created row from a user-lookup timeout, even though the token "
                        + "exchange itself already succeeded")
                .isEqualTo(before);
    }

    // Failure test 18 (Section 5.18): two concurrent first-time logins resolving to the SAME
    // x_user_id create exactly one community_manager row, not two.
    @Test
    void concurrentFirstTimeLoginsForSameXUserCreateExactlyOneRow() throws Exception {
        String sharedXUserId = "x-user-" + UUID.randomUUID();

        HttpResponse<Void> login1 = startLogin();
        String state1 = queryParam(login1.headers().firstValue("Location").orElseThrow(), "state");
        HttpResponse<Void> login2 = startLogin();
        String state2 = queryParam(login2.headers().firstValue("Location").orElseThrow(), "state");

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

        Runnable call1 = () -> {
            try {
                startLatch.countDown();
                startLatch.await();
                callback("code=" + code1 + "&state=" + state1);
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
                callback("code=" + code2 + "&state=" + state2);
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
    }

    // Failure test 19 (Section 5.19): a handle rename updates the SAME account, not a new one.
    @Test
    void handleRenameUpdatesSameAccountNotANewOne() throws Exception {
        String xUserId = "x-user-" + UUID.randomUUID();

        HttpResponse<Void> login1 = startLogin();
        String state1 = queryParam(login1.headers().firstValue("Location").orElseThrow(), "state");
        String code1 = "code-1-" + UUID.randomUUID();
        String accessToken1 = "access-1-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code1, accessToken1);
        stubUserLookupSuccess(accessToken1, xUserId, "old_handle");
        HttpResponse<String> first = callback("code=" + code1 + "&state=" + state1);
        assertThat(first.statusCode()).isBetween(200, 299);
        assertThat(handlesForXUserId(xUserId)).containsExactly("old_handle");

        HttpResponse<Void> login2 = startLogin();
        String state2 = queryParam(login2.headers().firstValue("Location").orElseThrow(), "state");
        String code2 = "code-2-" + UUID.randomUUID();
        String accessToken2 = "access-2-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code2, accessToken2);
        stubUserLookupSuccess(accessToken2, xUserId, "new_handle_after_rename");
        HttpResponse<String> second = callback("code=" + code2 + "&state=" + state2);
        assertThat(second.statusCode()).isBetween(200, 299);

        assertThat(countCommunityManagersByXUserId(xUserId))
                .as("a rename must update the same row, not create a second one")
                .isEqualTo(1);
        assertThat(handlesForXUserId(xUserId))
                .as("x_handle must be refreshed to the new value on every login")
                .containsExactly("new_handle_after_rename");
    }

    // Failure test 20 (Section 5.20): X's own tokens are discarded, not stored -- not in the
    // database, not in Redis, and not in any captured log line.
    @Test
    void xsOwnTokensAreDiscardedNotStored(CapturedOutput output) throws Exception {
        String xUserId = "x-user-" + UUID.randomUUID();
        HttpResponse<Void> loginResponse = startLogin();
        String state = queryParam(loginResponse.headers().firstValue("Location").orElseThrow(), "state");
        String code = "code-" + UUID.randomUUID();
        String xAccessToken = "x-access-token-very-secret-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, xAccessToken);
        stubUserLookupSuccess(xAccessToken, xUserId, "discard_me");

        HttpResponse<String> response = callback("code=" + code + "&state=" + state);
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

    // Happy path (Tests summary): OAuth login against mocked X endpoints -- callback upserts
    // the community_manager row and sets session cookies.
    // Also covers failure test 8 (Section 5.8): the real Set-Cookie headers from this real
    // response carry HttpOnly, Secure, and SameSite=Strict on BOTH the access and refresh
    // cookies.
    @Test
    void happyPathLoginCreatesRowAndSetsSessionCookiesWithExpectedFlags() throws Exception {
        String xUserId = "x-user-" + UUID.randomUUID();
        HttpResponse<Void> loginResponse = startLogin();
        assertThat(loginResponse.statusCode()).isEqualTo(302);
        String location = loginResponse.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith("https://x.com/i/oauth2/authorize");
        String state = queryParam(location, "state");
        assertThat(state).isNotNull();
        assertThat(queryParam(location, "code_challenge")).isNotNull();
        assertThat(queryParam(location, "code_challenge_method")).isEqualTo("S256");

        String code = "code-" + UUID.randomUUID();
        String accessToken = "access-" + UUID.randomUUID();
        stubTokenExchangeSuccess(code, accessToken);
        stubUserLookupSuccess(accessToken, xUserId, "happy_path_handle");

        HttpResponse<String> response = callback("code=" + code + "&state=" + state);
        assertThat(response.statusCode()).isBetween(200, 299);

        List<String> setCookies = response.headers().allValues("Set-Cookie");
        assertThat(setCookies).hasSizeGreaterThanOrEqualTo(2);

        boolean anyAccessCookie = false;
        boolean anyRefreshCookie = false;
        for (String cookie : setCookies) {
            assertThat(cookie).contains("HttpOnly").contains("Secure").contains("SameSite=Strict");
            if (cookie.toLowerCase().startsWith("accesstoken=")) {
                anyAccessCookie = true;
            }
            if (cookie.toLowerCase().startsWith("refreshtoken=")) {
                anyRefreshCookie = true;
            }
        }
        assertThat(anyAccessCookie).as("an access-token cookie must be set").isTrue();
        assertThat(anyRefreshCookie).as("a refresh-token cookie must be set").isTrue();

        assertThat(countCommunityManagersByXUserId(xUserId)).isEqualTo(1);
    }
}
