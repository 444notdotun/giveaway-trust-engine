package com.giveaway.giveawaytrustengine.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Wiring only (no business logic): translates this slice's auth-related exceptions into the
 * response codes PRD/CLAUDE.md call for -- 503 when a revocation check could not be completed
 * (Section 4), 401 when a token fails verification (Section 5, failure tests 4-6, 9).
 *
 * RED stub (slice 3) note: {@code @ExceptionHandler} only intercepts exceptions thrown from
 * within a dispatched Spring MVC handler method. {@link JwtAuthenticationFilter} currently throws
 * {@link JwtVerificationException} directly from {@code doFilter}, BEFORE the request ever
 * reaches the {@code DispatcherServlet} -- so this mapping does not yet actually catch that case
 * end-to-end for every endpoint. {@code ResolveEndpointFilterChainTest} exercises this honestly
 * and reports the real observed status rather than assuming this wiring alone makes it work.
 */
@RestControllerAdvice
public class AuthExceptionHandlers {

    @ExceptionHandler(RevocationCheckUnavailableException.class)
    public ResponseEntity<Void> onRevocationCheckUnavailable(RevocationCheckUnavailableException ex) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
    }

    @ExceptionHandler(JwtVerificationException.class)
    public ResponseEntity<Void> onJwtVerificationFailure(JwtVerificationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
