package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.config.CookieProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Chunk 4 review, item 4: {@code POST /auth/refresh} (not {@code GET} -- this mutates state,
 * rotating the token; see docs/slices/03-auth.md, Section 3a). Reads the {@code refreshToken}
 * cookie (now scoped to this exact path by {@link CookieProperties#refreshTokenPath()}), calls
 * the already-built-and-tested {@link RefreshTokenService#refresh(String)}, and sets the rotated
 * {@code accessToken}/{@code refreshToken} cookies with the same flags {@link OAuthLoginController}
 * uses at login.
 *
 * <p><b>Reuse, unknown token, malformed cookie, missing cookie, and expired all return the SAME
 * generic 401</b> -- empty body, no distinguishing detail -- matching the indistinguishability
 * {@link RefreshTokenService} already enforces internally (its own {@code GENERIC_REJECTION_MESSAGE}
 * discipline); this endpoint must not reopen that distinction at the HTTP layer by, say, giving
 * a different status or body for one case over another.
 *
 * <p><b>A genuine DB failure fails closed as 503</b> -- {@link RefreshTokenService#refresh(String)}
 * wraps a real {@code SQLException} (e.g. the row-level statement_timeout from item 2 firing
 * under contention) as {@link IllegalStateException}; that is not a statement about the token's
 * own validity, so it must never collapse into the 401 that means exactly that. A Redis failure
 * specifically can never reach this endpoint as a distinct failure mode: {@code
 * RefreshTokenService}'s own reuse-path Redis write is already swallowed internally (logged, not
 * rethrown), by design, so the generic 401 is the only observable outcome regardless of whether
 * that write succeeded.
 */
@RestController
public class RefreshController {

    private static final String REFRESH_COOKIE_NAME = "refreshToken";

    private final CookieProperties cookieProperties;
    private final ObjectProvider<RefreshTokenService> refreshTokenService;

    public RefreshController(CookieProperties cookieProperties, ObjectProvider<RefreshTokenService> refreshTokenService) {
        this.cookieProperties = cookieProperties;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<Void> refresh(HttpServletRequest request) {
        String cookieValue = readCookie(request, REFRESH_COOKIE_NAME);
        if (cookieValue == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        RefreshResult result;
        try {
            result = refreshTokenService.getObject().refresh(cookieValue);
        }
        catch (ReuseDetectedException | ExpiredRefreshTokenException invalid) {
            // Reuse, unknown token, malformed cookie, and expired are already indistinguishable
            // from each other inside RefreshTokenService -- caught together here so this layer
            // adds no new distinction either.
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        catch (IllegalStateException dbFailure) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }

        ResponseCookie accessCookie = sessionCookie(
                "accessToken", result.newAccessToken(), cookieProperties.path(), cookieProperties.accessTokenMaxAge());
        ResponseCookie refreshCookie = sessionCookie(
                REFRESH_COOKIE_NAME, result.newRefreshCookieValue(),
                cookieProperties.refreshTokenPath(), cookieProperties.refreshTokenMaxAge());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
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

    private static ResponseCookie sessionCookie(String name, String value, String path, Duration maxAge) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path(path)
                .maxAge(maxAge)
                .build();
    }
}
