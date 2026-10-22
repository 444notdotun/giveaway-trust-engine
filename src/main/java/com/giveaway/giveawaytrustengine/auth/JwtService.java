package com.giveaway.giveawaytrustengine.auth;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

/**
 * Issues and verifies access tokens. See docs/slices/03-auth.md, Section 2.
 *
 * RED stub (slice 3): {@link #issueAccessToken(UUID, UUID)} builds a real three-segment
 * base64url header/payload/signature shape (so structural assertions like "3 dot-separated
 * parts" already hold at this step) but the signature segment is a fixed placeholder, never a
 * real HMAC. {@link #verifyAccessToken(String)} always throws {@link JwtVerificationException}
 * with reason {@code "not-implemented"}, regardless of the token presented -- real HS256
 * verification, expiry checking, and algorithm-confusion rejection are not implemented yet.
 */
public class JwtService {

    private static final Duration ACCESS_TOKEN_LIFETIME = Duration.ofMinutes(15);
    private static final String PLACEHOLDER_SIGNATURE = "stub-signature";

    private final String signingKey;
    private final Clock clock;

    public JwtService(String signingKey, Clock clock) {
        this.signingKey = signingKey;
        this.clock = clock;
    }

    public String issueAccessToken(UUID cmId, UUID familyId) {
        long iat = clock.instant().getEpochSecond();
        long exp = clock.instant().plus(ACCESS_TOKEN_LIFETIME).getEpochSecond();

        String header = base64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = base64Url(String.format(
                "{\"sub\":\"%s\",\"familyId\":\"%s\",\"iat\":%d,\"exp\":%d}",
                cmId, familyId, iat, exp));
        String signature = base64Url(PLACEHOLDER_SIGNATURE);

        return header + "." + payload + "." + signature;
    }

    public AccessTokenClaims verifyAccessToken(String token) {
        throw new JwtVerificationException("not-implemented");
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
