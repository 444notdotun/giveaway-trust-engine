package com.giveaway.giveawaytrustengine.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * PKCE (RFC 7636) verifier/challenge generation, and this slice's OAuth {@code state} value.
 * See docs/slices/03-auth.md, Section 0.
 */
final class PkceChallenge {

    private static final SecureRandom RANDOM = new SecureRandom();

    private PkceChallenge() {
    }

    /** 32 random bytes, base64url (no padding) -- 43 characters, within RFC 7636's 43-128 range. */
    static String generateVerifier() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** {@code S256}: base64url(SHA-256(verifier)), never the plain verifier itself. */
    static String challengeFor(String verifier) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(verifier));
    }

    /**
     * 20 random bytes (160 bits), hex-encoded (40 characters) -- strictly more than the 128 bits
     * CLAUDE.md/the plan doc require, and strictly more entropy than a bare {@code UUID}'s 122
     * bits (6 fixed version/variant bits out of 128 nominal).
     */
    static String generateState() {
        byte[] bytes = new byte[20];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 must always be available", impossible);
        }
    }
}
