package com.giveaway.giveawaytrustengine.auth;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Resolves the caller's claims from the {@code accessToken} cookie via {@link JwtService} and
 * makes them available through {@link CurrentCommunityManager} for the rest of the request --
 * never from a request parameter, path variable, or body field (CLAUDE.md).
 *
 * Translates a failed verification to {@code 401} directly, in the filter itself, rather than
 * letting {@link JwtVerificationException} propagate uncaught: a plain servlet {@code Filter}
 * runs before {@code DispatcherServlet} ever dispatches to a handler, so a
 * {@code @ExceptionHandler} (see {@link AuthExceptionHandlers}) never gets a chance to see an
 * exception thrown from here -- that gap is exactly what left {@code ResolveEndpointFilterChainTest}
 * observing a raw {@code 500} instead of {@code 401} before this fix.
 *
 * No cookie at all is a different case from an invalid one: it is not itself a 401 here -- a
 * missing token just means no claims are set, and whichever endpoint actually requires
 * authentication (e.g. {@code ResolvePingController}) is responsible for rejecting that itself.
 * Not every endpoint requires a token (public routes exist per PRD Section 9), so this filter
 * stays permissive about absence and strict about invalidity.
 */
@Component
public class JwtAuthenticationFilter implements jakarta.servlet.Filter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    /** Chunk 4 review, item 1: one counter, tagged by reason, for every auth failure path. */
    private static final String FAILURE_COUNTER_NAME = "giveaway.auth.failure";

    private final JwtService jwtService;
    private final MeterRegistry meterRegistry;

    public JwtAuthenticationFilter(JwtService jwtService, MeterRegistry meterRegistry) {
        this.jwtService = jwtService;
        this.meterRegistry = meterRegistry;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String accessToken = readCookie(httpRequest, "accessToken");

        if (accessToken != null) {
            AccessTokenClaims claims;
            try {
                claims = jwtService.verifyAccessToken(accessToken);
            }
            catch (JwtVerificationException invalid) {
                // Never log the raw token -- only the machine-readable reason, matching slice
                // 2b's "log the reason, never the raw rejected value" discipline for this exact
                // class of event.
                log.warn("rejected access token: reason={}", invalid.reason());
                meterRegistry.counter(FAILURE_COUNTER_NAME, "reason", invalid.reason()).increment();
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            CurrentCommunityManager.set(claims);
        }

        try {
            chain.doFilter(request, response);
        }
        finally {
            CurrentCommunityManager.clear();
        }
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
}
