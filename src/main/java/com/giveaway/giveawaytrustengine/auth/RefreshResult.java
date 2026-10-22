package com.giveaway.giveawaytrustengine.auth;

import java.util.UUID;

/**
 * Result of a successful {@link RefreshTokenService#refresh(String)} call: a freshly issued
 * access token plus the rotated refresh-token cookie value for the same family.
 */
public record RefreshResult(String newAccessToken, String newRefreshCookieValue, UUID familyId) {
}
