package com.giveaway.giveawaytrustengine.logging;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Slice 2b: Structured logging. Plan doc: docs/slices/02b-structured-logging.md, Section 2
 * (requestId per HTTP request -- CRITICAL REVIEW on the sanitization path below) and Section 4
 * (the access log line).
 *
 * Puts a requestId into the MDC for the whole request, clears it in a finally block (even on
 * exceptions), and echoes it back as the {@code Rndr-Id} response header -- the same header name
 * Render's own platform sets, so a sanctioned inbound value correlates with Render's log explorer.
 * An inbound value is never trusted as-is: it is sanitized first (length-capped, charset-
 * restricted), and anything that fails either check is replaced wholesale with a freshly generated
 * UUID -- never truncated, never escaped-and-kept, never logged in its raw form. The filter also
 * never reads the request's query string, so a secret passed there can never reach the access log
 * line this filter emits.
 *
 * Registered at {@link Ordered#HIGHEST_PRECEDENCE} so it brackets the entire filter chain: no
 * other filter's log output can be missing a requestId, and the access log line below covers the
 * full request, not a partial view of it.
 *
 * Doc note for slice 5 and beyond: MDC is {@code ThreadLocal}-backed and does not propagate to
 * other threads. Slice 5's Apify calls (planned as concurrent {@code CompletableFuture}s) will
 * need to copy the context explicitly via {@code MDC.getCopyOfContextMap()} /
 * {@code MDC.setContextMap(...)} onto whatever executor thread runs them -- not needed yet, since
 * no such async work exists in this slice.
 *
 * Observability: a rejected inbound header (oversized or outside the allowed charset) is not a
 * silent fallback -- it logs one WARN line naming the rejection reason and the raw value's length
 * only (never the raw value itself), and increments a Micrometer counter tagged by reason, so an
 * operator can notice a client (proxy misconfiguration, or a probing attacker) sending malformed
 * {@code Rndr-Id} headers. An absent header is not a rejection -- it is the ordinary case of a
 * client with nothing to forward, so it generates a UUID silently.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestIdFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestIdFilter.class);

    static final String HEADER_NAME = "Rndr-Id";
    static final String MDC_KEY = "requestId";
    static final String REJECTED_HEADER_COUNTER_NAME = "giveaway.requestid.header.rejected";

    private static final int MAX_LENGTH = 64;
    private static final Pattern ALLOWED_CHARSET = Pattern.compile("^[A-Za-z0-9-]+$");

    private final MeterRegistry meterRegistry;

    public RequestIdFilter() {
        this(new SimpleMeterRegistry());
    }

    @Autowired
    public RequestIdFilter(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String requestId = sanitize(request.getHeader(HEADER_NAME));
        MDC.put(MDC_KEY, requestId);
        response.setHeader(HEADER_NAME, requestId);

        long startNanos = System.nanoTime();
        try {
            chain.doFilter(request, response);
        }
        finally {
            long durationMs = (System.nanoTime() - startNanos) / 1_000_000;
            log.info("{} {} {} {}ms", request.getMethod(), request.getRequestURI(), response.getStatus(), durationMs);
            MDC.remove(MDC_KEY);
        }
    }

    /**
     * CRITICAL REVIEW: the only path in this filter that touches untrusted, attacker-controlled
     * input before it reaches a log line or a response header. A value is accepted as-is only if
     * it is non-null, no longer than {@link #MAX_LENGTH}, and contains nothing outside
     * {@code [A-Za-z0-9-]} -- in particular no newline (which could forge a second log line) and
     * no runaway length (a resource-exhaustion vector independent of log injection). A null value
     * (no header sent at all) is the ordinary case and generates a UUID silently; any non-null
     * value that fails either check is a rejection, reported via {@link #rejectInvalidHeader} --
     * never truncated, never escaped-and-kept, and the raw value itself is never passed to a
     * logger, a metric tag, or a response header anywhere in this method.
     */
    private String sanitize(String raw) {
        if (raw == null) {
            return UUID.randomUUID().toString();
        }
        if (raw.length() > MAX_LENGTH) {
            return rejectInvalidHeader(raw.length(), "oversized");
        }
        if (!ALLOWED_CHARSET.matcher(raw).matches()) {
            return rejectInvalidHeader(raw.length(), "invalid-charset");
        }
        return raw;
    }

    private String rejectInvalidHeader(int length, String reason) {
        log.warn("rejected inbound {} header: reason={} length={}", HEADER_NAME, reason, length);
        meterRegistry.counter(REJECTED_HEADER_COUNTER_NAME, "reason", reason).increment();
        return UUID.randomUUID().toString();
    }
}
