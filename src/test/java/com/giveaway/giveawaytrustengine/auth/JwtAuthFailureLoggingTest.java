package com.giveaway.giveawaytrustengine.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Chunk 4 review, item 1: every {@link JwtService#verifyAccessToken(String)} failure reason
 * (expired, tampered-signature, alg-confusion, malformed-claims) must produce, through the real
 * {@link JwtAuthenticationFilter}, one WARN log line tagged {@code reason=...} and one increment
 * of {@code giveaway.auth.failure{reason=...}} -- and the log must never contain the rejected
 * token itself.
 *
 * Unit-level (mocked request/response, same pattern as {@code CmIdExtractionTest}), not a full
 * Spring context -- these are properties of {@code JwtAuthenticationFilter} + {@code JwtService}
 * alone, nothing else in the request pipeline is relevant to them.
 */
@ExtendWith(OutputCaptureExtension.class)
class JwtAuthFailureLoggingTest {

    private static final String SIGNING_KEY = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=";
    private static final Instant FIXED_NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    private HttpServletRequest requestWithAccessTokenCookie(String token) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("accessToken", token)});
        return request;
    }

    private void runFilter(JwtAuthenticationFilter filter, HttpServletRequest request) throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = (req, res) -> { };
        filter.doFilter(request, response, chain);
    }

    @Test
    void expiredTokenLogsReasonAndIncrementsCounter(CapturedOutput output) throws Exception {
        JwtService issuer = new JwtService(SIGNING_KEY, Clock.fixed(FIXED_NOW.minus(Duration.ofMinutes(20)), ZoneOffset.UTC));
        String expiredToken = issuer.issueAccessToken(UUID.randomUUID(), UUID.randomUUID());
        JwtService verifier = new JwtService(SIGNING_KEY, CLOCK);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(verifier, meterRegistry);

        runFilter(filter, requestWithAccessTokenCookie(expiredToken));

        assertThat(output.getAll()).contains("reason=expired");
        assertThat(output.getAll()).as("the rejected token must never be logged").doesNotContain(expiredToken);
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "expired").count()).isEqualTo(1.0);
    }

    @Test
    void tamperedSignatureLogsReasonAndIncrementsCounter(CapturedOutput output) throws Exception {
        JwtService service = new JwtService(SIGNING_KEY, CLOCK);
        String token = service.issueAccessToken(UUID.randomUUID(), UUID.randomUUID());
        String[] parts = token.split("\\.");
        byte[] sigBytes = Base64.getUrlDecoder().decode(parts[2]);
        sigBytes[0] = (byte) (sigBytes[0] ^ 0xFF);
        String tampered = parts[0] + "." + parts[1] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);

        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(service, meterRegistry);

        runFilter(filter, requestWithAccessTokenCookie(tampered));

        assertThat(output.getAll()).contains("reason=tampered-signature");
        assertThat(output.getAll()).as("the rejected token must never be logged").doesNotContain(tampered);
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "tampered-signature").count()).isEqualTo(1.0);
    }

    @Test
    void algorithmConfusionLogsReasonAndIncrementsCounter(CapturedOutput output) throws Exception {
        UUID cmId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(String.format(
                "{\"sub\":\"%s\",\"familyId\":\"%s\",\"iat\":%d,\"exp\":%d}",
                cmId, familyId, FIXED_NOW.getEpochSecond(), FIXED_NOW.plusSeconds(900).getEpochSecond()).getBytes());
        String algNoneToken = header + "." + payload + ".";

        JwtService service = new JwtService(SIGNING_KEY, CLOCK);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(service, meterRegistry);

        runFilter(filter, requestWithAccessTokenCookie(algNoneToken));

        assertThat(output.getAll()).contains("reason=alg-confusion");
        assertThat(output.getAll()).as("the rejected token must never be logged").doesNotContain(algNoneToken);
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "alg-confusion").count()).isEqualTo(1.0);
    }

    @Test
    void malformedClaimsLogsReasonAndIncrementsCounter(CapturedOutput output) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(SIGNING_KEY);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("not-a-valid-uuid")
                .claim("familyId", UUID.randomUUID().toString())
                .issueTime(Date.from(FIXED_NOW))
                .expirationTime(Date.from(FIXED_NOW.plus(Duration.ofMinutes(15))))
                .build();
        SignedJWT forged = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        forged.sign(new MACSigner(keyBytes));
        String forgedToken = forged.serialize();

        JwtService service = new JwtService(SIGNING_KEY, CLOCK);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(service, meterRegistry);

        runFilter(filter, requestWithAccessTokenCookie(forgedToken));

        assertThat(output.getAll()).contains("reason=malformed-claims");
        assertThat(output.getAll()).as("the rejected token must never be logged").doesNotContain(forgedToken);
        assertThat(meterRegistry.counter("giveaway.auth.failure", "reason", "malformed-claims").count()).isEqualTo(1.0);
    }
}
