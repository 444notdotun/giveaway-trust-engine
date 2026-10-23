package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.config.XOAuthProperties;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * The two outbound calls to X this slice ever makes: the token exchange and {@code GET
 * /2/users/me}. See docs/slices/03-auth.md, Section 0 -- "Hand-rolled, not Spring Security
 * OAuth2 Client," using {@code java.net.http.HttpClient} with an explicit connect timeout
 * ({@link HttpClient.Builder#connectTimeout(java.time.Duration)}) AND an explicit request/read
 * timeout ({@link HttpRequest.Builder#timeout(java.time.Duration)}) on every single request --
 * the same connect-vs-command distinction Section 1 draws for Redis. No retry: a login is an
 * interactive, human-initiated action, so the CM clicking "log in" again IS the retry.
 *
 * X's client credentials are sent once, in the token exchange's {@code Authorization: Basic}
 * header -- never logged, never embedded in any exception message. X's own access/refresh
 * tokens, once returned, are handed back to the caller as plain in-memory values and this class
 * never persists or logs them either; discarding them is {@link OAuthLoginController}'s
 * responsibility after the user lookup completes.
 */
public class XOAuthClient {

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Chunk 4 review, item 4: X's own response is validated, not trusted blindly. A numeric X
     * user id (up to 20 digits -- X ids are 64-bit integers) and a plausible X handle (letters,
     * digits, underscore, 1-15 characters, per X's own handle rules).
     */
    private static final Pattern X_USER_ID_PATTERN = Pattern.compile("^[0-9]{1,20}$");
    private static final Pattern X_USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_]{1,15}$");

    private final XOAuthProperties properties;
    private final HttpClient httpClient;

    public XOAuthClient(XOAuthProperties properties) {
        this.properties = properties;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(properties.connectTimeout())
                .build();
    }

    public record TokenExchangeResult(String accessToken) {
    }

    public record XUserInfo(String xUserId, String username) {
    }

    public TokenExchangeResult exchangeToken(String code, String codeVerifier) {
        String body = "grant_type=authorization_code"
                + "&code=" + encode(code)
                + "&redirect_uri=" + encode(properties.redirectUri())
                + "&code_verifier=" + encode(codeVerifier);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(properties.tokenUrl()))
                .timeout(properties.requestTimeout())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", basicAuthHeader())
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = send(request, "token exchange");
        if (response.statusCode() != 200) {
            throw new OAuthExchangeException("token exchange rejected");
        }

        JsonNode json = parseJson(response.body(), "token exchange");
        String accessToken = json.path("access_token").asString(null);
        if (accessToken == null || accessToken.isBlank()) {
            throw new OAuthExchangeException("token exchange response missing access_token");
        }
        return new TokenExchangeResult(accessToken);
    }

    public XUserInfo lookupUser(String xAccessToken) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(properties.userLookupUrl()))
                .timeout(properties.requestTimeout())
                .header("Authorization", "Bearer " + xAccessToken)
                .GET()
                .build();

        HttpResponse<String> response = send(request, "user lookup");
        if (response.statusCode() != 200) {
            throw new OAuthExchangeException("user lookup rejected");
        }

        JsonNode json = parseJson(response.body(), "user lookup");
        JsonNode data = json.path("data");
        String id = data.path("id").asString(null);
        String username = data.path("username").asString(null);
        if (id == null || id.isBlank() || username == null || username.isBlank()) {
            throw new OAuthExchangeException("user lookup response missing id/username");
        }
        if (!X_USER_ID_PATTERN.matcher(id).matches() || !X_USERNAME_PATTERN.matcher(username).matches()) {
            throw new OAuthExchangeException("user lookup response failed validation");
        }
        return new XUserInfo(id, username);
    }

    private HttpResponse<String> send(HttpRequest request, String callName) {
        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        }
        catch (HttpTimeoutException timeout) {
            throw new OAuthExchangeException(callName + " timed out", timeout);
        }
        catch (IOException | InterruptedException failure) {
            throw new OAuthExchangeException(callName + " failed", failure);
        }
    }

    private static JsonNode parseJson(String body, String callName) {
        try {
            return JSON.readTree(body);
        }
        catch (RuntimeException malformed) {
            throw new OAuthExchangeException(callName + " returned a malformed response", malformed);
        }
    }

    private String basicAuthHeader() {
        String credentials = properties.clientId() + ":" + properties.clientSecret();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
