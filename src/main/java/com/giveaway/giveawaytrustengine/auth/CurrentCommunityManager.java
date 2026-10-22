package com.giveaway.giveawaytrustengine.auth;

import jakarta.servlet.http.HttpServletRequest;

import java.util.UUID;

/**
 * Exposes the cmId resolved from the verified access token by {@link JwtAuthenticationFilter}
 * for the duration of the current request -- CLAUDE.md: "userId comes from the JWT, never from
 * request input." Never reads a request parameter, path variable, or body field.
 */
public final class CurrentCommunityManager {

    private static final ThreadLocal<UUID> CURRENT_CM_ID = new ThreadLocal<>();

    private CurrentCommunityManager() {
    }

    static void set(UUID cmId) {
        CURRENT_CM_ID.set(cmId);
    }

    static void clear() {
        CURRENT_CM_ID.remove();
    }

    /**
     * Returns the cmId resolved from the verified access token for this request. The
     * {@code request} parameter is accepted for API shape/future use but this stub never reads
     * anything from it directly -- the value comes only from what {@link JwtAuthenticationFilter}
     * already placed on the current thread.
     */
    public static UUID cmId(HttpServletRequest request) {
        return CURRENT_CM_ID.get();
    }
}
