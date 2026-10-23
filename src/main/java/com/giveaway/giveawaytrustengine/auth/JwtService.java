package com.giveaway.giveawaytrustengine.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Issues and verifies access tokens. See docs/slices/03-auth.md, Section 2.
 *
 * <p><b>Nimbus JOSE+JWT (10.10), approved 2026-10-23 -- see docs/slices/03-auth.md, Section 2,
 * "Open item 3, CLOSED."</b> {@code issueAccessToken} builds a {@link SignedJWT} and signs it
 * with {@link MACSigner}; {@code verifyAccessToken} inspects the header via the GENERIC
 * {@link JWTParser#parse(String)} -- not {@code SignedJWT.parse} directly -- so the algorithm
 * check runs BEFORE this class ever commits to treating the token as a signed JWT. That ordering
 * is what defeats algorithm confusion: a token asserting {@code alg: none} parses as a
 * {@code PlainJWT} (RFC 7515's unsecured JWS shape, which {@code SignedJWT.parse} itself cannot
 * even parse -- it throws, which this class would otherwise have had to interpret, rather than
 * decide, as an alg-confusion case), and a token asserting any algorithm other than {@code HS256}
 * (including a real signed algorithm like RS256) is rejected at the same header check, before any
 * verifier is constructed and before any signature is computed. This class only ever issues and
 * verifies ITS OWN tokens, in exactly one fixed shape, with exactly one algorithm -- it never
 * reads the token's own {@code alg} to select a verification strategy, only to reject anything
 * that isn't the one strategy this class has.
 *
 * <p>{@code exp}/{@code iat} are checked against the INJECTED {@link Clock}, never
 * {@code Instant.now()} and never Nimbus's own default-clock expiry helpers (CLAUDE.md: "time
 * comes from an injected Clock").
 *
 * <p>{@code sub} and {@code familyId} are parsed defensively: any malformed claim (not a
 * parseable UUID, missing, wrong type) becomes {@link JwtVerificationException} with reason
 * {@code malformed-claims}, so {@link JwtAuthenticationFilter} turns it into a 401, never an
 * uncaught exception propagating as a raw 500.
 *
 * <p>{@code signingKey} is the raw configured base64 string (see {@code app.jwt.signing-key},
 * validated and length-checked separately at startup by
 * {@code JwtSigningKeyGuardBeanFactoryPostProcessor}) -- decoded here to the real HMAC key bytes.
 * Nimbus's {@code MACSigner}/{@code MACVerifier} independently enforce a 256-bit (32-byte)
 * minimum for HS256 -- the same floor the startup guard already enforces, so production keys are
 * never affected; this is why the test fixtures that predated this length floor needed bumping
 * (see JwtServiceTest/CmIdExtractionTest).
 *
 * <p>Never logs a token or the signing key -- this class has no logging at all; a verification
 * failure's reason is the only thing a caller ever sees, via {@link JwtVerificationException}.
 */
public class JwtService {

    private static final Duration ACCESS_TOKEN_LIFETIME = Duration.ofMinutes(15);

    private final byte[] signingKeyBytes;
    private final Clock clock;

    public JwtService(String signingKey, Clock clock) {
        this.signingKeyBytes = Base64.getDecoder().decode(signingKey);
        this.clock = clock;
    }

    public String issueAccessToken(UUID cmId, UUID familyId) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(ACCESS_TOKEN_LIFETIME);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(cmId.toString())
                .claim("familyId", familyId.toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        try {
            jwt.sign(new MACSigner(signingKeyBytes));
        }
        catch (JOSEException impossible) {
            // Only thrown for a key too short or an unsupported algorithm -- both are fixed,
            // startup-time-verified facts about this class's own construction, never a runtime
            // condition this method's caller could hit.
            throw new IllegalStateException("failed to sign access token", impossible);
        }
        return jwt.serialize();
    }

    /**
     * Verification order is deliberate, not incidental: structure, then algorithm (via the
     * generic {@link JWTParser}, rejecting anything but {@code HS256} before a {@code SignedJWT}
     * is ever assumed, let alone a signature computed), then signature (Nimbus's own
     * constant-time HMAC comparison), then claim shape, then expiry. A tampered token with a
     * valid {@code alg} header fails at the signature step with reason
     * {@code tampered-signature}; a token asserting any other {@code alg} (including
     * {@code none}, or a genuinely different signed algorithm) fails at the algorithm step with
     * reason {@code alg-confusion}, before this class's own HMAC verification even runs.
     */
    public AccessTokenClaims verifyAccessToken(String token) {
        JWT parsed;
        try {
            parsed = JWTParser.parse(token);
        }
        catch (ParseException malformed) {
            throw new JwtVerificationException("malformed");
        }

        if (!JWSAlgorithm.HS256.equals(parsed.getHeader().getAlgorithm()) || !(parsed instanceof SignedJWT jwt)) {
            // Covers alg: none (parses as PlainJWT, whose header algorithm is Algorithm.NONE, not
            // equal to HS256), any other signed algorithm (RS256, HS384, ...), and an encrypted
            // JWT (EncryptedJWT) -- none of those are ever routed to a different verification
            // strategy; they are all rejected here, uniformly, before any verifier exists.
            throw new JwtVerificationException("alg-confusion");
        }

        try {
            if (!jwt.verify(new MACVerifier(signingKeyBytes))) {
                throw new JwtVerificationException("tampered-signature");
            }
        }
        catch (JOSEException verificationFailure) {
            throw new JwtVerificationException("tampered-signature");
        }

        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        }
        catch (ParseException malformed) {
            throw new JwtVerificationException("malformed-claims");
        }

        UUID cmId;
        UUID familyId;
        Instant issuedAt;
        Instant expiresAt;
        try {
            cmId = UUID.fromString(claims.getSubject());
            familyId = UUID.fromString(claims.getStringClaim("familyId"));
            issuedAt = claims.getIssueTime().toInstant();
            expiresAt = claims.getExpirationTime().toInstant();
        }
        catch (RuntimeException | ParseException malformed) {
            // Covers: sub/familyId missing or not a parseable UUID, familyId present but the
            // wrong JSON type, iat/exp missing (NullPointerException on .toInstant()). Every one
            // of these becomes the same reason -- the filter has no need to distinguish them, and
            // a 500 must never be the result of a claim merely looking different than expected.
            throw new JwtVerificationException("malformed-claims");
        }

        // Checked against the INJECTED Clock, never Instant.now() and never Nimbus's own
        // default-clock DefaultJWTClaimsVerifier (which would use the system clock internally).
        if (clock.instant().isAfter(expiresAt)) {
            throw new JwtVerificationException("expired");
        }

        return new AccessTokenClaims(cmId, familyId, issuedAt, expiresAt);
    }
}
