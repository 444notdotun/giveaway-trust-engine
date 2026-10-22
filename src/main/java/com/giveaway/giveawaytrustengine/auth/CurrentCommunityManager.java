package com.giveaway.giveawaytrustengine.auth;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.UUID;

/**
 * Exposes the claims resolved from the verified access token by {@link JwtAuthenticationFilter}
 * for the duration of the current request -- CLAUDE.md: "userId comes from the JWT, never from
 * request input." Never reads a request parameter, path variable, or body field.
 *
 * {@code familyId}/{@code issuedAt} are needed alongside {@code cmId} because revocation
 * (docs/slices/03-auth.md, Section 4) is keyed by familyId, not cmId, and the revocation-epoch
 * check (Section 4a) needs the token's own issuance time to decide whether it predates an epoch
 * reset.
 */
public final class CurrentCommunityManager {

    private static final ThreadLocal<AccessTokenClaims> CURRENT_CLAIMS = new ThreadLocal<>();

    private CurrentCommunityManager() {
    }

    static void set(AccessTokenClaims claims) {
        CURRENT_CLAIMS.set(claims);
    }

    static void clear() {
        CURRENT_CLAIMS.remove();
    }

    /**
     * Returns the cmId resolved from the verified access token for this request, or {@code null}
     * if no token was presented (or verification failed and the filter already rejected the
     * request before this could be read). The {@code request} parameter is accepted for API
     * shape/future use but this never reads anything from it directly -- the value comes only
     * from what {@link JwtAuthenticationFilter} already placed on the current thread.
     */
    public static UUID cmId(HttpServletRequest request) {
        AccessTokenClaims claims = CURRENT_CLAIMS.get();
        return claims != null ? claims.cmId() : null;
    }

    public static UUID familyId(HttpServletRequest request) {
        AccessTokenClaims claims = CURRENT_CLAIMS.get();
        return claims != null ? claims.familyId() : null;
    }

    public static Instant issuedAt(HttpServletRequest request) {
        AccessTokenClaims claims = CURRENT_CLAIMS.get();
        return claims != null ? claims.issuedAt() : null;
    }
}
