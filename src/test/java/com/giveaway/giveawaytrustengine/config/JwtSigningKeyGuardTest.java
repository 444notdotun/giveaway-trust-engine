package com.giveaway.giveawaytrustengine.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Slice 3 (Auth), Section 2 and "Tests summary".
 * Plan doc: docs/slices/03-auth.md, Section 2 ("Signing key: environment variable, no default,
 * minimum length enforced at startup") and "Tests summary" (the guard's own startup-refusal
 * tests, same CapturedOutput pattern as {@link StartupGuardTest}).
 *
 * RED: {@code JwtSigningKeyGuardBeanFactoryPostProcessor} does not exist yet -- this is expected
 * to fail to compile until slice 3's GREEN step adds it.
 *
 * Mirrors {@link StartupGuardTest}'s own doc comment about never asserting only an in-memory
 * return value: every case here asserts the real startup failure (root cause type + message)
 * AND the real captured ERROR log line, never one without the other.
 */
@ExtendWith(OutputCaptureExtension.class)
class JwtSigningKeyGuardTest {

    private static final String GUARD_LOGGER = "JwtSigningKeyGuardBeanFactoryPostProcessor";
    // 32 bytes exactly -- the minimum this guard is specified to accept.
    private static final String VALID_32_BYTE_KEY = "01234567890123456789012345678901".substring(0, 32);

    private static ApplicationContextRunner guardedContext() {
        return new ApplicationContextRunner()
                .withBean(JwtSigningKeyGuardBeanFactoryPostProcessor.class);
    }

    private static Throwable rootCause(AssertableApplicationContext context) {
        Throwable failure = context.getStartupFailure();
        assertThat(failure).as("expected a startup failure but context did not fail").isNotNull();
        Throwable cursor = failure;
        while (cursor.getCause() != null) {
            cursor = cursor.getCause();
        }
        return cursor;
    }

    private static void assertErrorLogLine(CapturedOutput output) {
        boolean found = output.getOut().lines()
                .anyMatch(line -> line.contains("ERROR") && line.contains(GUARD_LOGGER));
        assertThat(found)
                .as("expected one ERROR log line from " + GUARD_LOGGER + " but captured output was:\n"
                        + output.getOut())
                .isTrue();
    }

    // Case 1: app.jwt.signing-key missing entirely -- refuses to start.
    @Test
    void missingSigningKeyRefusesToStart(CapturedOutput output) {
        guardedContext()
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root.getMessage()).containsIgnoringCase("app.jwt.signing-key");
                    assertErrorLogLine(output);
                    // CLAUDE.md: never log or return the signing key -- nothing to leak here
                    // since the value is absent, but the message/log must still name the
                    // property, not dump whatever (empty) value was bound.
                });
    }

    // Case 2: app.jwt.signing-key present but shorter than 32 bytes (UTF-8 decoded) -- refuses.
    @Test
    void tooShortSigningKeyRefusesToStart(CapturedOutput output) {
        String tooShort = "short-key-only-16b"; // 18 bytes, well under 32
        guardedContext()
                .withPropertyValues("app.jwt.signing-key=" + tooShort)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root.getMessage()).containsIgnoringCase("app.jwt.signing-key");
                    assertErrorLogLine(output);
                    assertThat(output.getAll())
                            .as("the signing key value itself must never appear in logs, even when rejected")
                            .doesNotContain(tooShort);
                });
    }

    // Happy path: a signing key of exactly 32 UTF-8 bytes starts successfully.
    @Test
    void exactly32ByteSigningKeyStarts(CapturedOutput output) {
        guardedContext()
                .withPropertyValues("app.jwt.signing-key=" + VALID_32_BYTE_KEY)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(output.getAll())
                            .as("the signing key value itself must never appear in logs, even on success")
                            .doesNotContain(VALID_32_BYTE_KEY);
                });
    }

    // Blank (whitespace-only) signing key must be treated as missing, not as a too-short value
    // that happens to pass some other check -- same whitespace discipline as StartupGuardTest.
    @Test
    void whitespaceOnlySigningKeyRefusesToStart(CapturedOutput output) {
        guardedContext()
                .withInitializer(context -> context.getEnvironment().getPropertySources().addFirst(
                        new org.springframework.core.env.MapPropertySource("raw-test-value",
                                java.util.Map.of("app.jwt.signing-key", "   "))))
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root.getMessage()).containsIgnoringCase("app.jwt.signing-key");
                    assertErrorLogLine(output);
                });
    }
}
