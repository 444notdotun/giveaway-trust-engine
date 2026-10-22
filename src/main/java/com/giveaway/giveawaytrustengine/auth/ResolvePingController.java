package com.giveaway.giveawaytrustengine.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * Test-only "resolve-style" endpoint (wiring, matching PRD Section 15's check order for real
 * resolve endpoints -- no real resolve endpoint exists yet, see docs/slices/03-auth.md, Section
 * 4, "Honest scope boundary, carried forward") -- lets {@code ResolveEndpointFilterChainTest}
 * exercise the real {@link JwtAuthenticationFilter} + {@link RevocationChecker} +
 * {@link AuthExceptionHandlers} wiring end to end over a real HTTP request.
 *
 * Check order: missing token -> 401 (no claims at all to check anything else against); revoked
 * family -> 401; an unreachable Redis during that check -> 503, via
 * {@link RevocationCheckUnavailableException} propagating out to {@link AuthExceptionHandlers}
 * (this one DOES reach the handler, since it's thrown from inside a dispatched controller
 * method, unlike {@link JwtVerificationException} which the filter itself must translate).
 *
 * Takes {@code ObjectProvider<RevocationChecker>} rather than {@code RevocationChecker} directly
 * -- {@link AuthBeansConfig#revocationChecker} returns {@code null} in contexts without Redis
 * autoconfiguration; see that class's own Javadoc for why.
 */
@RestController
public class ResolvePingController {

    private final ObjectProvider<RevocationChecker> revocationChecker;
    private final Clock clock;

    public ResolvePingController(ObjectProvider<RevocationChecker> revocationChecker, Clock clock) {
        this.revocationChecker = revocationChecker;
        this.clock = clock;
    }

    @GetMapping("/resolve/ping")
    public ResponseEntity<Void> ping(HttpServletRequest request) {
        UUID familyId = CurrentCommunityManager.familyId(request);
        Instant issuedAt = CurrentCommunityManager.issuedAt(request);
        if (familyId == null || issuedAt == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        boolean revoked = revocationChecker.getObject().isFamilyRevoked(familyId, issuedAt);
        if (revoked) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok().build();
    }
}
