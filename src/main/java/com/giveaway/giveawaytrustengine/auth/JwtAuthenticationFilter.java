package com.giveaway.giveawaytrustengine.auth;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Resolves the caller's cmId from the {@code accessToken} cookie via {@link JwtService} and
 * makes it available through {@link CurrentCommunityManager} for the rest of the request --
 * never from a request parameter, path variable, or body field (CLAUDE.md).
 *
 * RED stub (slice 3): reads the cookie and calls {@link JwtService#verifyAccessToken(String)},
 * which (per that class's own RED stub) always throws {@link JwtVerificationException}. That
 * exception is allowed to propagate here rather than being translated to a 401 response -- the
 * real translation is not implemented yet.
 *
 * {@code @Component} registers this as a real servlet filter bean (Spring Boot auto-registers
 * any {@code Filter} bean, same as {@code RequestIdFilter} in slice 2b) -- wiring only, no new
 * behavior. {@code ResolveEndpointFilterChainTest} exercises this through a real HTTP request.
 */
@Component
public class JwtAuthenticationFilter implements Filter {

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String accessToken = readCookie(httpRequest, "accessToken");

        if (accessToken != null) {
            AccessTokenClaims claims = jwtService.verifyAccessToken(accessToken);
            CurrentCommunityManager.set(claims.cmId());
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
