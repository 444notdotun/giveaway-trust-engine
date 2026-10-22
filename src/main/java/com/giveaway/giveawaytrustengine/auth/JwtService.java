package com.giveaway.giveawaytrustengine.auth;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Issues and verifies access tokens. See docs/slices/03-auth.md, Section 2.
 *
 * Hand-rolled HS256, not a JWT library (Nimbus JOSE+JWT remains unapproved as a new dependency --
 * docs/slices/03-auth.md, Open item 3). This is narrower and lower-risk than a general-purpose
 * hand-rolled JWT verifier would be: this class only ever issues and verifies ITS OWN tokens, in
 * exactly one fixed shape, with exactly one algorithm. It never branches its verification
 * strategy on anything the token itself claims -- {@code alg} is read from the header only to be
 * checked against the one value this class ever accepts ({@code HS256}); a token claiming any
 * other value is rejected before a signature is even computed, not routed to a different
 * (nonexistent) verification path. This is the specific property that defeats algorithm
 * confusion, including {@code alg: none}.
 *
 * {@code signingKey} is the raw configured base64 string (see {@code app.jwt.signing-key},
 * validated and length-checked separately at startup by
 * {@code JwtSigningKeyGuardBeanFactoryPostProcessor}) -- decoded here to the real HMAC key bytes,
 * the same decode-then-use rule the startup guard enforces the minimum length against.
 */
public class JwtService {

    private static final Duration ACCESS_TOKEN_LIFETIME = Duration.ofMinutes(15);
    private static final String EXPECTED_ALG = "HS256";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final byte[] signingKeyBytes;
    private final Clock clock;

    public JwtService(String signingKey, Clock clock) {
        this.signingKeyBytes = Base64.getDecoder().decode(signingKey);
        this.clock = clock;
    }

    public String issueAccessToken(UUID cmId, UUID familyId) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(ACCESS_TOKEN_LIFETIME);

        ObjectNode header = JSON.createObjectNode();
        header.put("alg", EXPECTED_ALG);
        header.put("typ", "JWT");

        ObjectNode payload = JSON.createObjectNode();
        payload.put("sub", cmId.toString());
        payload.put("familyId", familyId.toString());
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", expiresAt.getEpochSecond());

        String signingInput = base64UrlJson(header) + "." + base64UrlJson(payload);
        String signature = base64UrlBytes(hmac(signingInput));
        return signingInput + "." + signature;
    }

    /**
     * Verification order is deliberate, not incidental: structure, then algorithm (rejecting
     * anything but {@code HS256} before a signature is ever computed), then signature (constant
     * time comparison), then expiry. A tampered token with a valid {@code alg} header fails at
     * the signature step with reason {@code tampered-signature}; a token asserting any other
     * {@code alg} (including {@code none}) fails at the algorithm step with reason
     * {@code alg-confusion}, before this class's own HMAC computation even runs.
     */
    public AccessTokenClaims verifyAccessToken(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new JwtVerificationException("malformed");
        }
        String headerSegment = parts[0];
        String payloadSegment = parts[1];
        String signatureSegment = parts[2];

        JsonNode header;
        JsonNode payload;
        try {
            header = JSON.readTree(Base64.getUrlDecoder().decode(headerSegment));
            payload = JSON.readTree(Base64.getUrlDecoder().decode(payloadSegment));
        }
        catch (RuntimeException malformed) {
            throw new JwtVerificationException("malformed");
        }

        String alg = header.path("alg").asString("");
        if (!EXPECTED_ALG.equals(alg)) {
            throw new JwtVerificationException("alg-confusion");
        }

        byte[] expectedSignature = hmac(headerSegment + "." + payloadSegment);
        byte[] actualSignature;
        try {
            actualSignature = Base64.getUrlDecoder().decode(signatureSegment);
        }
        catch (IllegalArgumentException notBase64) {
            throw new JwtVerificationException("tampered-signature");
        }
        if (!MessageDigest.isEqual(expectedSignature, actualSignature)) {
            throw new JwtVerificationException("tampered-signature");
        }

        UUID cmId = UUID.fromString(payload.path("sub").asString());
        UUID familyId = UUID.fromString(payload.path("familyId").asString());
        Instant issuedAt = Instant.ofEpochSecond(payload.path("iat").asLong());
        Instant expiresAt = Instant.ofEpochSecond(payload.path("exp").asLong());

        if (clock.instant().isAfter(expiresAt)) {
            throw new JwtVerificationException("expired");
        }

        return new AccessTokenClaims(cmId, familyId, issuedAt, expiresAt);
    }

    private byte[] hmac(String signingInput) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(signingKeyBytes, HMAC_ALGORITHM));
            return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
        }
        catch (java.security.NoSuchAlgorithmException | InvalidKeyException impossible) {
            throw new IllegalStateException("HmacSHA256 must always be available", impossible);
        }
    }

    private static String base64UrlJson(JsonNode node) {
        return base64UrlBytes(JSON.writeValueAsString(node).getBytes(StandardCharsets.UTF_8));
    }

    private static String base64UrlBytes(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
