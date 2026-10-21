package com.giveaway.giveawaytrustengine.logging;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.MDC;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Slice 2b: Structured logging.
 * Plan doc: docs/slices/02b-structured-logging.md, Section 2 (requestId per HTTP request --
 * CRITICAL REVIEW on the sanitization path) and Section 4 (one access log line per request).
 * PRD Section 14 (Observability -- "Structured JSON logs with giveawayId in the MDC, plus a
 * requestId per request").
 *
 * Every test here drives {@link RequestIdFilter#doFilter} directly against mocked
 * {@code HttpServletRequest}/{@code HttpServletResponse}/{@code FilterChain} rather than a real
 * HTTP round-trip: most HTTP client/server stacks already reject a raw "\n" inside a header value
 * before it would reach application code, so a mock-based test is the only way to actually
 * exercise the filter's own sanitization logic (test 1 and 2 below) rather than relying on a
 * lower layer having already blocked the forged input.
 */
@ExtendWith(OutputCaptureExtension.class)
class RequestIdFilterTest {

    private static final String HEADER_NAME = "Rndr-Id";
    private static final Pattern UUID_PATTERN =
            Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private static HttpServletRequest mockRequest(String rndrIdHeader) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(HEADER_NAME)).thenReturn(rndrIdHeader);
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/ping");
        return request;
    }

    private static HttpServletResponse mockResponse() {
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getStatus()).thenReturn(200);
        return response;
    }

    private static String capturedHeaderValue(HttpServletResponse response) {
        org.mockito.ArgumentCaptor<String> captor = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq(HEADER_NAME), captor.capture());
        return captor.getValue();
    }

    // Failure test 1 (Section 5.1): forged header with an embedded newline -- the filter must
    // generate a fresh UUID rather than let the raw value anywhere near the response header or
    // the log output, which is exactly what would let an attacker forge a second, fake log line.
    @Test
    void forgedHeaderWithEmbeddedNewlineIsRejectedAndFreshUuidIsGenerated(CapturedOutput output) throws Exception {
        String forged = "abc\ndef";
        HttpServletRequest request = mockRequest(forged);
        HttpServletResponse response = mockResponse();
        FilterChain chain = (req, res) -> { };

        new RequestIdFilter().doFilter(request, response, chain);

        String responseHeaderValue = capturedHeaderValue(response);
        assertThat(responseHeaderValue).isNotEqualTo(forged);
        assertThat(responseHeaderValue).matches(UUID_PATTERN);
        assertThat(output.getAll()).doesNotContain("abc\ndef");
        assertThat(output.getOut().lines().noneMatch(line -> line.trim().equals("def")))
                .as("no injected second log line consisting only of the forged suffix")
                .isTrue();
        assertThat(output.getAll())
                .as("operator-visible WARN line naming the rejection reason, never the raw value")
                .contains("WARN")
                .contains("invalid-charset")
                .doesNotContain(forged);
    }

    // Failure test 2 (Section 5.2): forged header, grossly oversized (~10,000 chars) -- same
    // assertions: generates fresh, response header is the fresh value, oversized value never
    // reaches the log output (a resource-exhaustion vector independent of log injection).
    @Test
    void forgedHeaderThatIsGrosslyOversizedIsRejectedAndFreshUuidIsGenerated(CapturedOutput output) throws Exception {
        String forged = "a".repeat(10_000);
        HttpServletRequest request = mockRequest(forged);
        HttpServletResponse response = mockResponse();
        FilterChain chain = (req, res) -> { };

        new RequestIdFilter().doFilter(request, response, chain);

        String responseHeaderValue = capturedHeaderValue(response);
        assertThat(responseHeaderValue).isNotEqualTo(forged);
        assertThat(responseHeaderValue).hasSizeLessThan(100);
        assertThat(responseHeaderValue).matches(UUID_PATTERN);
        assertThat(output.getAll()).doesNotContain(forged);
        assertThat(output.getAll())
                .as("operator-visible WARN line naming the rejection reason, never the raw value")
                .contains("WARN")
                .contains("oversized")
                .doesNotContain(forged);
    }

    // Observability (CLAUDE.md: "Micrometer counters ... for the events the slice introduces" and
    // "each failure test also asserts the log line or metric an operator would see"): a rejected
    // header increments a Micrometer counter tagged by rejection reason, not just a silent
    // fallback to a fresh UUID.
    @Test
    void rejectedHeaderIncrementsMicrometerCounterTaggedByReason() throws Exception {
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        RequestIdFilter filter = new RequestIdFilter(meterRegistry);
        FilterChain chain = (req, res) -> { };

        filter.doFilter(mockRequest("abc\ndef"), mockResponse(), chain);
        filter.doFilter(mockRequest("a".repeat(10_000)), mockResponse(), chain);
        filter.doFilter(mockRequest(null), mockResponse(), chain);
        filter.doFilter(mockRequest("valid-request-id-123"), mockResponse(), chain);

        assertThat(meterRegistry.counter(RequestIdFilter.REJECTED_HEADER_COUNTER_NAME, "reason", "invalid-charset")
                .count())
                .as("exactly one rejection tagged invalid-charset, from the newline-forged header")
                .isEqualTo(1.0);
        assertThat(meterRegistry.counter(RequestIdFilter.REJECTED_HEADER_COUNTER_NAME, "reason", "oversized")
                .count())
                .as("exactly one rejection tagged oversized, from the 10,000-char header")
                .isEqualTo(1.0);
    }

    // Failure test 3 (Section 5.3): requestId must not leak across requests reusing the same
    // thread -- two sequential doFilter calls on the same (JUnit test) thread must observe two
    // different requestId values, proving the second request's MDC value isn't the first
    // request's value accidentally surviving in the ThreadLocal.
    @Test
    void requestIdDoesNotLeakAcrossRequestsOnReusedThread() throws Exception {
        AtomicReference<String> firstRequestId = new AtomicReference<>();
        AtomicReference<String> secondRequestId = new AtomicReference<>();

        RequestIdFilter filter = new RequestIdFilter();

        filter.doFilter(mockRequest(null), mockResponse(),
                (req, res) -> firstRequestId.set(MDC.get("requestId")));
        filter.doFilter(mockRequest(null), mockResponse(),
                (req, res) -> secondRequestId.set(MDC.get("requestId")));

        assertThat(firstRequestId.get()).isNotNull();
        assertThat(secondRequestId.get()).isNotNull();
        assertThat(secondRequestId.get())
                .as("second request's requestId must not be the first request's value surviving the ThreadLocal")
                .isNotEqualTo(firstRequestId.get());
        assertThat(MDC.get("requestId"))
                .as("finally block must clear the MDC after a normal (non-exception) request completes too, "
                        + "not only on the exception path covered by the next test")
                .isNull();
    }

    // Failure test 4 (Section 5.4): requestId is present in the MDC while an exception propagates
    // out of the downstream chain, and the finally-block cleanup still runs on that path --
    // MDC.get("requestId") must be null again immediately after doFilter returns via the
    // exception, proving the cleanup isn't only a happy-path behavior.
    @Test
    void requestIdIsPresentDuringExceptionPropagationAndMdcIsClearedAfter() {
        AtomicReference<String> idDuringException = new AtomicReference<>();
        RuntimeException boom = new RuntimeException("downstream handler exploded");

        RequestIdFilter filter = new RequestIdFilter();
        FilterChain chain = (req, res) -> {
            idDuringException.set(MDC.get("requestId"));
            throw boom;
        };

        assertThatThrownBy(() -> filter.doFilter(mockRequest(null), mockResponse(), chain))
                .isSameAs(boom);

        assertThat(idDuringException.get())
                .as("requestId must be in the MDC while the exception is propagating")
                .isNotNull();
        assertThat(MDC.get("requestId"))
                .as("finally block must clear the MDC even on the exception path")
                .isNull();
    }

    // Failure test 5 (Section 4 / Section 5.5): a secret in the query string must never appear
    // anywhere in the captured log output, and more strongly, the filter must never even read
    // the query string -- request.getQueryString() is verified as never invoked.
    @Test
    void secretInQueryStringNeverAppearsInLogOutputAndIsNeverRead(CapturedOutput output) throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(HEADER_NAME)).thenReturn(null);
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/some/path");
        when(request.getQueryString()).thenReturn("token=supersecret123");
        HttpServletResponse response = mockResponse();
        FilterChain chain = (req, res) -> { };

        new RequestIdFilter().doFilter(request, response, chain);

        verify(request, never()).getQueryString();
        assertThat(output.getAll()).doesNotContain("supersecret123");
    }

    // Happy path: no inbound Rndr-Id header -- a server-generated UUID is used, and it is the
    // same value in both the MDC (observed by the downstream chain) and the response header.
    @Test
    void noInboundHeaderGeneratesServerSideUuidConsistentInMdcAndResponseHeader() throws Exception {
        AtomicReference<String> mdcValueDuringRequest = new AtomicReference<>();
        HttpServletRequest request = mockRequest(null);
        HttpServletResponse response = mockResponse();

        new RequestIdFilter().doFilter(request, response,
                (req, res) -> mdcValueDuringRequest.set(MDC.get("requestId")));

        String responseHeaderValue = capturedHeaderValue(response);
        assertThat(responseHeaderValue).matches(UUID_PATTERN);
        assertThat(mdcValueDuringRequest.get()).isEqualTo(responseHeaderValue);
    }

    // Happy path: a VALID inbound Rndr-Id header (passes length + charset checks) is preserved
    // as-is in both the MDC and the response header -- not needlessly replaced.
    @Test
    void validInboundHeaderIsPreservedAsIsInMdcAndResponseHeader() throws Exception {
        String validId = "valid-request-id-123";
        AtomicReference<String> mdcValueDuringRequest = new AtomicReference<>();
        HttpServletRequest request = mockRequest(validId);
        HttpServletResponse response = mockResponse();

        new RequestIdFilter().doFilter(request, response,
                (req, res) -> mdcValueDuringRequest.set(MDC.get("requestId")));

        String responseHeaderValue = capturedHeaderValue(response);
        assertThat(responseHeaderValue).isEqualTo(validId);
        assertThat(mdcValueDuringRequest.get()).isEqualTo(validId);
    }

    // Happy path (Section 4): the access-log line itself contains method, path, status and
    // duration for an ordinary successful request.
    @Test
    void accessLogLineContainsMethodPathStatusAndDurationForSuccessfulRequest(CapturedOutput output) throws Exception {
        HttpServletRequest request = mockRequest(null);
        HttpServletResponse response = mockResponse();

        new RequestIdFilter().doFilter(request, response, (req, res) -> { });

        String all = output.getAll();
        assertThat(all).contains("GET").contains("/ping").contains("200");
        assertThat(Pattern.compile("\\b\\d+\\s?ms\\b").matcher(all).find())
                .as("expected a duration in milliseconds somewhere in the access log line")
                .isTrue();
    }
}
