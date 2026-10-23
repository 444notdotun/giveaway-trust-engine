package com.giveaway.giveawaytrustengine.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Slice 3 (Auth), Section 2 and Section 5 (failure tests 4, 5, 6) + happy-path access-token
 * verification (Tests summary).
 * Plan doc: docs/slices/03-auth.md.
 *
 * RED: {@code JwtService} and {@code JwtVerificationException} do not exist yet.
 *
 * Every time-dependent assertion goes through an injected {@link Clock#fixed}, never
 * {@code Thread.sleep} (CLAUDE.md: "time comes from an injected Clock").
 *
 * Tests 5 and 6 hand-construct the malicious token as a raw base64url string -- no JWT library
 * is used to build a bad token, only (at GREEN) to verify one, per this slice's own instruction
 * that Nimbus is not yet approved for this RED step.
 */
class JwtServiceTest {

    // Decodes to 32 bytes (256 bits) -- Nimbus's MACSigner/MACVerifier hard-enforce this as the
    // HS256 minimum (item 0 of the chunk 4 review); the old 24-byte value here predated that
    // constraint and was already below the production startup guard's own 32-byte minimum
    // (JwtSigningKeyGuardBeanFactoryPostProcessor), so this fixture was never representative of
    // a real key to begin with.
    private static final String SIGNING_KEY = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
    private static final Instant FIXED_NOW = Instant.parse("2026-10-21T12:00:00Z");

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    // Failure test 4 (Section 5.4): an expired access token is rejected -- exp in the past
    // relative to the injected Clock, not wall-clock Instant.now().
    @Test
    void expiredAccessTokenIsRejected() {
        UUID cmId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();

        Clock issuanceClock = Clock.fixed(FIXED_NOW.minus(Duration.ofMinutes(16)), ZoneOffset.UTC);
        JwtService issuer = new JwtService(SIGNING_KEY, issuanceClock);
        String token = issuer.issueAccessToken(cmId, familyId);

        // Verify 16 minutes later -- one minute past the 15-minute lifetime.
        Clock verificationClock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        JwtService verifier = new JwtService(SIGNING_KEY, verificationClock);

        assertThatThrownBy(() -> verifier.verifyAccessToken(token))
                .isInstanceOf(JwtVerificationException.class)
                .satisfies(ex -> assertThat(((JwtVerificationException) ex).reason()).isEqualTo("expired"));
    }

    // Failure test 5 (Section 5.5): flip one byte of a validly-issued token's signature segment
    // -- must fail verification, not fail at some later unrelated step.
    @Test
    void tamperedSignatureIsRejected() {
        Clock clock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        JwtService service = new JwtService(SIGNING_KEY, clock);
        String token = service.issueAccessToken(UUID.randomUUID(), UUID.randomUUID());

        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(3);
        byte[] sigBytes = Base64.getUrlDecoder().decode(parts[2]);
        sigBytes[0] = (byte) (sigBytes[0] ^ 0xFF); // flip every bit of the first byte
        String tamperedSig = Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);
        String tampered = parts[0] + "." + parts[1] + "." + tamperedSig;

        assertThatThrownBy(() -> service.verifyAccessToken(tampered))
                .isInstanceOf(JwtVerificationException.class)
                .satisfies(ex -> assertThat(((JwtVerificationException) ex).reason())
                        .isEqualTo("tampered-signature"));
    }

    // Failure test 6 (Section 5.6): algorithm confusion -- a hand-built token with
    // header {"alg":"none"} and no signature segment must be rejected outright, because the
    // verifier is configured to accept only HS256 and never reads the token's own "alg" header
    // to choose a verification strategy.
    @Test
    void algorithmConfusionNoneIsRejected() {
        UUID cmId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        String header = base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = base64Url(String.format(
                "{\"sub\":\"%s\",\"familyId\":\"%s\",\"iat\":%d,\"exp\":%d}",
                cmId, familyId, FIXED_NOW.getEpochSecond(), FIXED_NOW.plusSeconds(900).getEpochSecond()));
        String algNoneToken = header + "." + payload + ".";

        Clock clock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        JwtService service = new JwtService(SIGNING_KEY, clock);

        assertThatThrownBy(() -> service.verifyAccessToken(algNoneToken))
                .isInstanceOf(JwtVerificationException.class)
                .satisfies(ex -> assertThat(((JwtVerificationException) ex).reason())
                        .isEqualTo("alg-confusion"));
    }

    // Item 0 (chunk 4 review): algorithm confusion via a genuinely DIFFERENT signed algorithm,
    // not just alg:none. A token signed with HS384 is still a real SignedJWT (unlike alg:none,
    // which parses as a PlainJWT and would be rejected by a much weaker check -- e.g. "is this
    // even a SignedJWT instance" -- that the alg:none test alone can't distinguish from a correct
    // HS256-only check). This isolates that the explicit HS256 pin is what's doing the work, not
    // merely "is this token's shape signed at all."
    @Test
    void algorithmConfusionHs384IsRejected() throws Exception {
        UUID cmId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(cmId.toString())
                .claim("familyId", familyId.toString())
                .issueTime(Date.from(FIXED_NOW))
                .expirationTime(Date.from(FIXED_NOW.plus(Duration.ofMinutes(15))))
                .build();
        byte[] hs384Key = new byte[48]; // HS384's own 384-bit minimum -- irrelevant to the check being tested
        new SecureRandom().nextBytes(hs384Key);
        SignedJWT hs384Token = new SignedJWT(new JWSHeader(JWSAlgorithm.HS384), claims);
        hs384Token.sign(new MACSigner(hs384Key));

        Clock clock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        JwtService service = new JwtService(SIGNING_KEY, clock);

        assertThatThrownBy(() -> service.verifyAccessToken(hs384Token.serialize()))
                .isInstanceOf(JwtVerificationException.class)
                .satisfies(ex -> assertThat(((JwtVerificationException) ex).reason())
                        .isEqualTo("alg-confusion"));
    }

    // Happy-path access-token verification (Tests summary): valid signature, not expired, and
    // claims (cmId, familyId) extracted correctly.
    @Test
    void validUnexpiredTokenVerifiesAndExtractsClaimsCorrectly() {
        UUID cmId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        Clock clock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        JwtService service = new JwtService(SIGNING_KEY, clock);

        String token = service.issueAccessToken(cmId, familyId);
        AccessTokenClaims claims = service.verifyAccessToken(token);

        assertThat(claims.cmId()).isEqualTo(cmId);
        assertThat(claims.familyId()).isEqualTo(familyId);
        assertThat(claims.issuedAt()).isEqualTo(FIXED_NOW);
        assertThat(claims.expiresAt()).isEqualTo(FIXED_NOW.plus(Duration.ofMinutes(15)));
    }
}
