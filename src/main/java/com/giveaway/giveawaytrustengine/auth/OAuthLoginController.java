package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.config.CookieProperties;
import com.giveaway.giveawaytrustengine.config.XOAuthProperties;
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
import java.time.Duration;
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
        String state = oauthStateService.getObject().createState(verifier);

        String redirectTo = oAuthProperties.authorizeUrl()
                + "?response_type=" + enc("code")
                + "&client_id=" + enc(oAuthProperties.clientId())
                + "&redirect_uri=" + enc(oAuthProperties.redirectUri())
                + "&scope=" + enc("users.read tweet.read")
                + "&state=" + enc(state)
                + "&code_challenge=" + enc(challenge)
                + "&code_challenge_method=" + enc("S256");

        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(redirectTo)).build();
    }

    @GetMapping("/auth/callback")
    public ResponseEntity<Void> callback(@RequestParam Map<String, String> params) {
        // X's own error parameter (e.g. the CM declined on X's consent screen): a clean 4xx,
        // never a stack trace and never an echo of the raw error text back to the browser.
        if (params.containsKey("error")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        String state = params.get("state");
        String code = params.get("code");
        if (state == null || code == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        // Single-use, atomic GETDEL -- missing, unknown, and already-consumed (replay) states
        // are all indistinguishable from the outside, same rejection either way.
        String codeVerifier = oauthStateService.getObject().consumeVerifier(state);
        if (codeVerifier == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        String xAccessToken;
        XOAuthClient.XUserInfo userInfo;
        try {
            xAccessToken = xOAuthClient.exchangeToken(code, codeVerifier).accessToken();
            userInfo = xOAuthClient.lookupUser(xAccessToken);
        }
        catch (OAuthExchangeException exchangeFailure) {
            // Clean failure, no half-created row -- nothing has been written to the database yet
            // at this point, regardless of which of the two calls failed.
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
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
                .build();
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
