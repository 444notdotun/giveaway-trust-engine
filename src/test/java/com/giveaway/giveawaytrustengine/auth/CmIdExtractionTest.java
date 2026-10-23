package com.giveaway.giveawaytrustengine.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Slice 3 (Auth), Section 5, failure test 9.
 * Plan doc: docs/slices/03-auth.md -- "userId/cmId always comes from the verified JWT, never
 * from a request body or path parameter."
 *
 * RED: {@code JwtAuthenticationFilter}, {@code JwtService}, and {@code CurrentCommunityManager}
 * do not exist yet.
 *
 * Tested at the extraction-point level (the component that pulls cmId out of the authenticated
 * request context), per the plan's own note: no endpoint in this slice varies behavior by a
 * body/path-supplied cmId yet.
 */
class CmIdExtractionTest {

    // Decodes to 32 bytes (256 bits) -- Nimbus's MACSigner/MACVerifier hard-enforce this as the
    // HS256 minimum (item 0 of the chunk 4 review); the old 24-byte value here predated that
    // constraint.
    private static final String SIGNING_KEY = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
    private static final Instant FIXED_NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    // Failure test 9 (Section 5.9): a request whose body/path/query claims a DIFFERENT cmId than
    // the caller's own valid JWT must still resolve to the JWT's cmId -- the extraction
    // component never reads cmId from anywhere else, and never even looks at the shadowing
    // request parameter.
    @Test
    void cmIdAlwaysComesFromVerifiedJwtNeverFromRequestParameterOrAttribute() throws Exception {
        UUID realCmId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        UUID attackerClaimedCmId = UUID.randomUUID();

        JwtService jwtService = new JwtService(SIGNING_KEY, CLOCK);
        String validAccessToken = jwtService.issueAccessToken(realCmId, familyId);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("accessToken", validAccessToken)});
        // The attacker-controlled shadow value, as if it came from a request body/path/query.
        when(request.getParameter("cmId")).thenReturn(attackerClaimedCmId.toString());
        HttpServletResponse response = mock(HttpServletResponse.class);

        AtomicReference<UUID> resolvedDuringRequest = new AtomicReference<>();
        FilterChain chain = (req, res) -> resolvedDuringRequest.set(
                CurrentCommunityManager.cmId((HttpServletRequest) req));

        new JwtAuthenticationFilter(jwtService).doFilter(request, response, chain);

        assertThat(resolvedDuringRequest.get())
                .as("cmId must come from the verified JWT, never the attacker-claimed request parameter")
                .isEqualTo(realCmId)
                .isNotEqualTo(attackerClaimedCmId);
        verify(request, never()).getParameter("cmId");
    }
}
