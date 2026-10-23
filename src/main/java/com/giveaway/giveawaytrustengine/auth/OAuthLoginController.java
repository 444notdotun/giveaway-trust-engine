package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.config.CookieProperties;
import com.giveaway.giveawaytrustengine.config.XOAuthProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

/**
 * OAuth 2.0 Authorization Code + PKCE login against X. See docs/slices/03-auth.md, Section 0
 * (flow), Section 3 (cookies).
 *
 * <p><b>redirect_uri always comes from {@link XOAuthProperties#redirectUri()}</b> -- never from
 * the inbound request (no {@code Host} header, no caller-supplied parameter is ever consulted).
 * This is the one thing standing between this endpoint and an open redirect: X itself enforces
 * the registered callback URL must match exactly, and that enforcement is only meaningful if
 * this app always sends the same fixed, configured value.
 *
 * <p><b>No DB transaction is ever open across an X call.</b> Both {@link XOAuthClient} calls
 * (token exchange, user lookup) complete and return before {@link CommunityManagerRepository} is
 * ever touched; the upsert's own transaction starts only after X can no longer be slow or down
 * for this request.
 *
 * <p><b>X's own access/refresh tokens are discarded</b> -- held only in the local
 * {@code xAccessToken} variable for the duration of this one request, never passed to anything
 * that persists or logs it, and gone once this method returns.
 */
@RestController
public class OAuthLoginController {

    /**
     * Chunk 4 review, item 1 (login CSRF). {@code SameSite=Lax}, NOT {@code Strict} -- this
     * cookie must still be present when X's cross-site, top-level redirect lands on
     * {@code /auth/callback}, which a {@code Strict} cookie would never be. {@code Path=/auth}
     * scopes it away from every other endpoint; it carries no information on its own (it's
     * compared against a hash stored server-side), so scoping it narrowly is defense in depth,
     * not load-bearing secrecy.
     */
    private static final String BINDING_COOKIE_NAME = "oauthBinding";
    private static final String BINDING_COOKIE_PATH = "/auth";
    private static final Duration BINDING_COOKIE_MAX_AGE = Duration.ofSeconds(300);

    private final XOAuthProperties oAuthProperties;
    private final CookieProperties cookieProperties;
    private final ObjectProvider<OAuthStateService> oauthStateService;
    private final XOAuthClient xOAuthClient;
    private final ObjectProvider<CommunityManagerRepository> communityManagerRepository;
    private final ObjectProvider<RefreshTokenService> refreshTokenService;

    public OAuthLoginController(XOAuthProperties oAuthProperties, CookieProperties cookieProperties,
            ObjectProvider<OAuthStateService> oauthStateService, XOAuthClient xOAuthClient,
            ObjectProvider<CommunityManagerRepository> communityManagerRepository,
            ObjectProvider<RefreshTokenService> refreshTokenService) {
        this.oAuthProperties = oAuthProperties;
        this.cookieProperties = cookieProperties;
        this.oauthStateService = oauthStateService;
        this.xOAuthClient = xOAuthClient;
        this.communityManagerRepository = communityManagerRepository;
        this.refreshTokenService = refreshTokenService;
    }

    @GetMapping("/auth/login")
    public ResponseEntity<Void> login() {
        String verifier = PkceChallenge.generateVerifier();
        String challenge = PkceChallenge.challengeFor(verifier);
        OAuthStateService.StateCreationResult created = oauthStateService.getObject().createState(verifier);

        String redirectTo = oAuthProperties.authorizeUrl()
                + "?response_type=" + enc("code")
                + "&client_id=" + enc(oAuthProperties.clientId())
                + "&redirect_uri=" + enc(oAuthProperties.redirectUri())
                + "&scope=" + enc("users.read tweet.read")
                + "&state=" + enc(created.state())
                + "&code_challenge=" + enc(challenge)
                + "&code_challenge_method=" + enc("S256");

        ResponseCookie bindingCookie = ResponseCookie.from(BINDING_COOKIE_NAME, created.bindingNonce())
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .path(BINDING_COOKIE_PATH)
                .maxAge(BINDING_COOKIE_MAX_AGE)
                .build();

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(redirectTo))
                .header(HttpHeaders.SET_COOKIE, bindingCookie.toString())
                .build();
    }

    @GetMapping("/auth/callback")
    public ResponseEntity<Void> callback(HttpServletRequest request, @RequestParam Map<String, String> params) {
        // X's own error parameter (e.g. the CM declined on X's consent screen): a clean 4xx,
        // never a stack trace and never an echo of the raw error text back to the browser.
        if (params.containsKey("error")) {
            return badRequestClearingBindingCookie();
        }

        String state = params.get("state");
        String code = params.get("code");
        if (state == null || code == null) {
            return badRequestClearingBindingCookie();
        }

        // Single-use, atomic GETDEL -- taken FIRST, so a mismatched or missing binding cookie
        // still burns the state: a second attempt (with or without the correct cookie) can never
        // retry against the same state/code pair (chunk 4 review, item 1).
        OAuthStateService.ConsumedState consumed = oauthStateService.getObject().consumeState(state);
        if (consumed == null) {
            return badRequestClearingBindingCookie();
        }

        String bindingCookieValue = readCookie(request, BINDING_COOKIE_NAME);
        if (bindingCookieValue == null || !bindingMatches(bindingCookieValue, consumed.bindingHashHex())) {
            // Missing and mismatched are rejected identically -- same generic 400 either way, no
            // distinguishing detail leaked about which case this was.
            return badRequestClearingBindingCookie();
        }

        String xAccessToken;
        XOAuthClient.XUserInfo userInfo;
        try {
            xAccessToken = xOAuthClient.exchangeToken(code, consumed.codeVerifier()).accessToken();
            userInfo = xOAuthClient.lookupUser(xAccessToken);
        }
        catch (OAuthExchangeException exchangeFailure) {
            // Clean failure, no half-created row -- nothing has been written to the database yet
            // at this point, regardless of which of the two calls failed.
            return badRequestClearingBindingCookie();
        }
        // xAccessToken is never used again past this point -- discarded, not persisted or logged.

        CommunityManagerRepository.UpsertResult upsertResult = communityManagerRepository.getObject()
                .upsertByXUserId(userInfo.xUserId(), userInfo.username());

        UUID familyId = UUID.randomUUID();
        RefreshResult refreshResult = refreshTokenService.getObject()
                .issueInitialRefreshToken(upsertResult.cmId(), familyId);

        ResponseCookie accessCookie = sessionCookie(
                "accessToken", refreshResult.newAccessToken(), cookieProperties.accessTokenMaxAge());
        ResponseCookie refreshCookie = sessionCookie(
                "refreshToken", refreshResult.newRefreshCookieValue(), cookieProperties.refreshTokenMaxAge());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .header(HttpHeaders.SET_COOKIE, clearingBindingCookie().toString())
                .build();
    }

    /** Every /auth/callback rejection clears the binding cookie -- it's single-use either way. */
    private ResponseEntity<Void> badRequestClearingBindingCookie() {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .header(HttpHeaders.SET_COOKIE, clearingBindingCookie().toString())
                .build();
    }

    private ResponseCookie clearingBindingCookie() {
        return ResponseCookie.from(BINDING_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .path(BINDING_COOKIE_PATH)
                .maxAge(Duration.ZERO)
                .build();
    }

    private static String readCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /** Constant-time: hashes the cookie's own value and compares byte-for-byte via {@code MessageDigest.isEqual}. */
    private static boolean bindingMatches(String cookieValue, String storedBindingHashHex) {
        byte[] actual = HexFormat.of().parseHex(PkceChallenge.sha256Hex(cookieValue));
        byte[] expected = HexFormat.of().parseHex(storedBindingHashHex);
        return MessageDigest.isEqual(actual, expected);
    }

    private ResponseCookie sessionCookie(String name, String value, Duration maxAge) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path(cookieProperties.path())
                .maxAge(maxAge)
                .build();
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
