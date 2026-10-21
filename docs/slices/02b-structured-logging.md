# Slice 2b: Structured logging

Not globally CRITICAL REVIEW. **CRITICAL REVIEW applies only to the inbound requestId header sanitization** (Section 2 below) — that's the one piece of this slice with an actual untrusted-input attack surface; everything else is internal formatting/plumbing. PRD refs: Section 14 (Observability — "Structured JSON logs with giveawayId in the MDC, plus a requestId per request"). BUILD_ORDER item 2b, inserted after slice 2a.

## 1. Structured JSON console output: Spring Boot's built-in support, no new dependency

**Verified against Spring Boot's own reference docs for this version line** (fetched directly, not recalled from memory): `logging.structured.format.console` is the property; three built-in formats ship with plain `spring-boot-starter-logging` (Logback) — **no extra dependency, no `logstash-logback-encoder`, nothing to add to `pom.xml`**:
- `ecs` (Elastic Common Schema)
- `gelf` (Graylog Extended Log Format)
- `logstash` (classic Logstash JSON format)

All three automatically include every MDC key-value pair in the emitted JSON object — this is the mechanism that gets `requestId` (and, later, `giveawayId`) into every log line for free, with no manual field-mapping code.

**Format chosen: `ecs`.** Set via `logging.structured.format.console=ecs` in `application.properties`. Reasoning: this project has no committed log aggregator yet (Render's own log stream is the only consumer right now, per slice 2a Section 7) — `ecs` (Elastic Common Schema) is a vendor-neutral, widely-adopted schema designed specifically to not lock a project into one platform, which fits "no committed destination yet" better than `gelf` (Graylog-specific) or even `logstash` (ELK-specific, though also broadly supported). If a specific log platform gets adopted later and prefers a different shape, this is a one-line property change, not a re-architecture — nothing else in this slice depends on which of the three formats is chosen, since the MDC-inclusion behavior is identical across all three.

Example of what one line will actually look like (per Spring Boot's own documented example shape, adapted to this app):
```json
{"@timestamp":"2026-01-01T10:15:00.067462556Z","log.level":"INFO","message":"startup guard passed: environment=DEV bachsMode=SANDBOX","process.thread.name":"main","service.name":"giveaway-trust-engine","log.logger":"com.giveaway.giveawaytrustengine.config.StartupGuardBeanFactoryPostProcessor","ecs.version":"8.11","requestId":"..."}
```
(`requestId` would only appear on a request-scoped log line — the startup guard's own lines run before any HTTP request exists, so they won't carry one; see Section 3.)

## 2. requestId per HTTP request — CRITICAL REVIEW on the sanitization path

A `jakarta.servlet.Filter` (registered early in the filter chain) wraps every request:

```
String raw = request.getHeader("X-Request-Id");
String requestId = sanitize(raw);  // see below; null/invalid raw -> generates one
MDC.put("requestId", requestId);
response.setHeader("X-Request-Id", requestId);
try {
    chain.doFilter(request, response);
} finally {
    MDC.remove("requestId");
}
```

**The `finally` block is load-bearing, not decorative.** `MDC` is backed by a `ThreadLocal`, and application servers (Tomcat included) reuse worker threads across requests from a pool — if `MDC.remove` only ran on the happy path, a request that throws would leave its `requestId` sitting in that thread's `ThreadLocal`, ready to silently attach itself to whatever unrelated request the pool hands that thread next. The `finally` guarantees cleanup on every exit path, including an uncaught exception propagating out of `chain.doFilter`.

**Sanitization, since an inbound header is untrusted input:**
- **Generated server-side by default.** If no `X-Request-Id` header is present, a fresh UUID is generated — this is the common case and needs no validation.
- **If a header value is present, it's sanitized before anything else touches it:**
  - **Length-capped.** A UUID is 36 characters; cap accepted length well above that (e.g. 64 characters) to allow other reasonable ID formats some callers might send, but reject anything grossly oversized — an unbounded header value is itself a resource-exhaustion vector (a client sending a multi-megabyte header value), independent of what it does to a log line.
  - **Charset-restricted.** Only `[A-Za-z0-9-]` accepted (matching typical ID shapes, including UUIDs) — this is what directly defeats a log-injection attempt: a header value containing `\n`, `\r`, or other control characters could otherwise forge what looks like a second, fake log line/field inside a single real one. Rejecting anything outside this charset closes that off at the source, not by trying to escape dangerous characters after the fact.
  - **A value that fails either check is never used, in any form.** The filter falls back to generating a fresh UUID instead — it does **not** truncate the bad value and use the truncated remainder, does **not** strip the bad characters and use what's left, and critically does **not** let the raw rejected value reach a log line "for debugging" (e.g. logging `"rejected invalid requestId header: <raw value>"` would just relocate the injection into a different log line). The failure is silent to the attacker (they get a normal response with a server-generated `X-Request-Id`, no error indicating their header was rejected) but never silent in the sense of "the bad value quietly made it into a log somewhere" — it provably never does, because it's never referenced again after the validation check fails.
- **Returned as a response header**, `X-Request-Id`, carrying whichever value is actually in effect (the client's own, if it passed validation, or the freshly generated one if it didn't or if none was sent) — so a caller can always correlate their request against server-side logs using the value Spring Boot actually used, not assume their own header round-tripped unchanged.

## 3. The startup guard's existing log lines, in the new format

The guard (slice 2) runs before any HTTP request exists, so its INFO/ERROR lines never carry a `requestId` — nothing in this slice changes that, and nothing needs to.

**`StartupGuardTest`'s existing assertions should still hold, unchanged — verified, not assumed.** `assertErrorLogLine` (and the plain `.contains("INFO")`/`.contains("ERROR")` checks on the happy-path tests) are substring checks against the raw captured output line, not checks anchored to the old bare-Logback-default console pattern. Under `ecs` format:
- `"ERROR"` / `"INFO"` still appear verbatim as the `log.level` field's string value.
- The logger's simple name (`StartupGuardBeanFactoryPostProcessor`) still appears as a substring of the `log.logger` field's fully-qualified value.
- Every property/environment/mode substring the tests check for (`"STAGING"`, `"app.bachs.base-url"`, etc.) still appears verbatim inside the `message` field's JSON-escaped string value, since those come from the same `log.info(...)`/`log.error(...)` calls in `StartupGuardBeanFactoryPostProcessor.java`, completely unchanged by this slice.

This gets confirmed by actually running the existing `StartupGuardTest` suite once `logging.structured.format.console=ecs` is set, in GREEN — not just reasoned through here. **If any assertion breaks, the plan is to fix the assertion to match the new (still-correct) format, with a comment explaining why, rather than loosen the format choice to avoid touching the test.** Expectation going in: none should break, per the reasoning above, but this gets proven, not assumed.

## 4. Failure tests, written first

1. **Forged header: embedded newline.** `X-Request-Id: abc\ndef` (or the HTTP-layer-safe equivalent a test can actually send — most HTTP clients/servers reject a raw `\n` in a header value before it reaches application code at all, so this test may need to go through the filter directly with a crafted `HttpServletRequest` mock rather than a real HTTP round-trip, to actually exercise the sanitization logic rather than relying on a lower layer to have already blocked it). Assert: the filter generates a fresh UUID instead, the response's `X-Request-Id` header is that fresh UUID (not the forged value, not even a truncated/escaped version of it), and the captured log output for that request contains neither the literal forged value nor any sign of a second, injected-looking log line.
2. **Forged header: very long value** (e.g. 10,000 characters). Same assertions as above — generates fresh, response header is the fresh value, log output never contains the oversized value.
3. **requestId does not leak across requests on a reused thread.** Simulate two sequential requests through the same filter instance on the same thread (e.g. call the filter's `doFilter` twice in a row within one test method, with two different mock request/response pairs, both referencing the same thread by construction since JUnit runs the test method on one thread) — assert the second request's captured requestId is different from the first's, and specifically that it is **not** the first request's value accidentally surviving in the `ThreadLocal`.
4. **requestId is still present and logged on an exception path.** A filter chain where the downstream handler throws — assert `MDC.get("requestId")` is non-null and matches what the filter set *while the exception is propagating* (so a log line emitted during exception handling still carries it), and assert `MDC.get("requestId")` is `null` again immediately after `doFilter` returns (via the exception) — proving the `finally` cleanup ran even on this path, which is also what prevents test case 3's leak scenario from happening after an error, not only after success.

Every one of these asserts the actual log output (via `CapturedOutput`, same pattern as `StartupGuardTest`), not just the in-memory MDC state — the point is proving what a log line actually contains, since that's the thing an operator or an attacker would actually see.

## 5. Never logged: wallet address, Bachs URLs, secrets, request bodies

This slice introduces no new path that would log any of these — `extractedWallet` doesn't exist as a concept until slice 6 (cleaning pipeline) populates it, there's no request-body logging anywhere in this app, and the Bachs-URL-redaction discipline already established in slice 2 (`StartupGuardTest` asserting `output.getAll()).doesNotContain(FAKE_SANDBOX_URL)` etc.) is untouched by this slice's changes.

**Where real redaction infrastructure would live, if it's ever needed beyond "just don't pass it as a log argument":** Spring Boot's structured logging support allows a fully custom formatter via `logging.structured.format.console=<fully-qualified-class-name>` implementing `StructuredLogFormatter<ILoggingEvent>` — a custom formatter could inspect and mask specific field values (e.g. a field literally named `extractedWallet`) before serialization, as a backstop beyond "the code that logs things is disciplined about what it passes." That's not built in this slice — CLAUDE.md's existing rule ("Never log or return extractedWallet. Redact before logging at every level") is enforced today, and will keep being enforced going forward, by the same discipline-plus-test-assertion pattern already used for the Bachs URLs: never pass the sensitive value as a log argument in the first place, and assert its absence from captured output in whichever test exercises the code path that touches it. A structured-formatter-level backstop is a reasonable future hardening step once there's an actual `extractedWallet`-touching code path to protect (slice 6+), not something to build speculatively now against a value that doesn't exist yet.

## 6. giveawayId MDC: still deferred to slice 5

Unchanged from slice 2a's decision. No giveaway exists until slice 5 (Create giveaway) creates the first one; adding an MDC key for a value that can't exist yet would be dead code. The structured-format plumbing this slice adds (Section 1) means slice 5 only has to call `MDC.put("giveawayId", ...)` at the right point — no formatter/encoder work will be needed then, since every format chosen here already includes arbitrary MDC keys automatically.

## 7. Acceptance on staging

The existing slice 2a pipeline (merge to `main` → `verify` → `image` build/push/content-check → Render deploy hook → `/actuator/info` commit-poll verification) carries this slice to staging exactly the way it already proved it can for slice 2a — no new deploy mechanism needed. Acceptance is: **Adedotun reads one real JSON log line from Render's actual log stream** after this deploys, confirming the structured format is really what's landing in production log output, not just what a local test captures.

## Tests summary

Four failure tests (Section 4) plus: a binding/format test confirming `logging.structured.format.console=ecs` actually produces parseable JSON for a sample log line (parse the captured line with a JSON parser, don't just eyeball it); re-running the full existing `StartupGuardTest`/`AppPropertiesBindingTest` suite unchanged to confirm no regression (Section 3); a happy-path test confirming a request with no `X-Request-Id` header gets a server-generated UUID that's consistent between the MDC value used during the request and the response header value; a happy-path test confirming a *valid* inbound `X-Request-Id` header (passes length+charset checks) is preserved as-is in both the MDC and the response header, not needlessly replaced.
