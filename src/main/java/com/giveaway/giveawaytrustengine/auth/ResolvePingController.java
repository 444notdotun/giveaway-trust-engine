package com.giveaway.giveawaytrustengine.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.util.UUID;

/**
 * Test-only "resolve-style" endpoint (wiring only, no business logic) -- lets
 * {@code ResolveEndpointFilterChainTest} exercise the REAL {@link JwtAuthenticationFilter} +
 * {@link RevocationChecker} + {@link AuthExceptionHandlers} wiring end to end over a real HTTP
 * request, per PRD Section 15 ("resolve endpoints" consult Redis on every call). No real resolve
 * endpoint exists yet (first one arrives in a later slice) -- see docs/slices/03-auth.md, Section
 * 4, "Honest scope boundary, carried forward".
 *
 * Takes {@code ObjectProvider<RevocationChecker>} rather than {@code RevocationChecker} directly
 * -- {@link AuthBeansConfig#revocationChecker} returns {@code null} in contexts without Redis
 * autoconfiguration, and a {@code null}-returning {@code @Bean} method does not satisfy a plain,
 * required constructor dependency elsewhere (Spring raises {@code NoSuchBeanDefinitionException}
 * at the dependent site in that case -- observed directly against {@code StartupGuardTest} and
 * {@code StructuredLoggingIntegrationTest}'s minimal contexts). {@code ObjectProvider} sidesteps
 * that: nothing calls {@link #ping(HttpServletRequest)} in those contexts anyway.
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
        UUID cmId = CurrentCommunityManager.cmId(request);
        UUID familyIdStandIn = cmId != null ? cmId : UUID.randomUUID();
        revocationChecker.getObject().isFamilyRevoked(familyIdStandIn, clock.instant());
        return ResponseEntity.ok().build();
    }
}
