package com.giveaway.giveawaytrustengine.auth;

import java.time.Instant;
import java.util.UUID;

/**
 * Claims extracted from a verified access token. See {@link JwtService#verifyAccessToken(String)}.
 */
public record AccessTokenClaims(UUID cmId, UUID familyId, Instant issuedAt, Instant expiresAt) {
}
